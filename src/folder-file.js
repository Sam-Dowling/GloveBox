'use strict';
// ════════════════════════════════════════════════════════════════════════════
// folder-file.js — synthetic File-like representing a dropped folder root
//
// Why this exists
// ───────────────
// Loupe's load pipeline (`App._loadFile`) is keyed on a single `File` going
// through `RenderRoute.run` → `RendererRegistry.detect` → a per-id renderer
// in `App._rendererDispatch`. To support folder ingest WITHOUT inventing a
// parallel session/multi-file concept, we model a dropped folder as a
// **synthetic top-level archive**: one virtual `File` carrying a flat
// `_loupeFolderEntries` list, dispatched to `FolderRenderer` (which mounts
// `ArchiveTree` and emits `open-inner-file` for each leaf — the same
// drill-down protocol every archive renderer uses today).
//
// Contract
// ────────
//   • Quacks like a `File`: `{ name, size, type, lastModified }` + an
//     async `arrayBuffer()` returning a zero-byte `ArrayBuffer`. The
//     load pipeline never reads bytes from a folder root — IOC sweep,
//     encoded-content scan, and auto-YARA all skip when
//     `file._loupeFolderEntries` is set (see `app-load.js`).
//   • Carries `_loupeFolderEntries`: a flat list of
//     `{ path, dir, size, file?, mtime? }` records. Leaves carry a real
//     `File` (`.file`); directories carry only `path` + `dir: true`.
//     Paths are relative to the folder root, forward-slash separated,
//     without a leading slash. They MUST NOT include the root name as
//     a leading segment — the synthetic root IS the dropped folder, and
//     `FolderRenderer.render` paints `📁 <name>` in its own header. A
//     leaf at the top level of `forensics/` has path `file.txt`, not
//     `forensics/file.txt`. `ArchiveTree` consumes this shape directly.
//   • `size` is the sum of leaf sizes — used by the breadcrumb / file-info
//     panel and by the per-dispatch size cap (folder dispatch sets the cap
//     to `Number.POSITIVE_INFINITY` since the bytes are virtual anyway).
//   • Plain ES class — does NOT extend `File`. No code path in Loupe
//     uses `instanceof File` (verified at write time); duck-typing is
//     sufficient and avoids the read-only `Blob.size` foot-gun.
//
// Construction is the **only** authorised place that creates a synthetic
// folder root. Multi-file loose drops and `webkitGetAsEntry()`-walked
// directory drops both route through `App._ingestFolderOrFiles`
// (`app-core.js`), which calls the static `FolderFile.fromEntries(...)`.
// ════════════════════════════════════════════════════════════════════════════

class FolderFile {
  /**
   * @param {string} name           Display name (folder basename, or the
   *                                synthetic "Dropped files" label for
   *                                multi-file loose drops).
   * @param {Array<{path:string, dir:boolean, size:number,
   *                file?:File, mtime?:Date}>} entries
   *                                Flat entry list; see contract above.
   */
  constructor(name, entries) {
    this.name = String(name || 'folder');
    if (!Array.isArray(entries)) entries = [];
    // Defensive freeze so renderers can't mutate the entry list and have
    // it observed by the budget / nav-stack snapshot machinery.
    this._loupeFolderEntries = entries;
    this.entries = entries; // alias for readability at call sites
    let total = 0;
    for (const e of entries) {
      if (e && !e.dir && Number.isFinite(e.size) && e.size > 0) total += e.size;
    }
    this.size = total;
    this.type = '';                 // synthetic — no MIME
    this.lastModified = Date.now();
  }

  /** Folder roots have no on-disk bytes. The load pipeline never reads
   *  this (auto-YARA / IOC sweep / encoded-content scan all gate on
   *  `_loupeFolderEntries`), but we honour the File-like contract so a
   *  stray caller doesn't NPE. */
  async arrayBuffer() { return new ArrayBuffer(0); }

  /** Same File-like contract — empty string for folder roots. */
  async text() { return ''; }

  /**
   * Build a FolderFile from raw `webkitGetAsEntry()` results plus any
   * loose top-level files. Walks every directory entry breadth-first
   * up to `PARSER_LIMITS.MAX_FOLDER_ENTRIES` (4 096 by default), then
   * returns `{ folder: FolderFile, truncated: boolean, walkedCount }`.
   *
   * Directory walking is async (FileSystem API uses callbacks). The
   * caller (`App._ingestFolderOrFiles`) awaits this before kicking
   * `_loadFile`. A single oversized folder is truncated rather than
   * rejected — the analyst still gets the first N entries plus a
   * visible `IOC.INFO` row from `FolderRenderer.analyzeForSecurity`.
   *
   * @param {string} rootName        Display name for the root.
   * @param {Array<{entry?: any, file?: File, path?: string,
   *                asRoot?: boolean}>} sources
   *        Mixed ingress descriptors:
   *          - `{ entry: FileSystemEntry, asRoot?: true }` —
   *            call entry.file/readEntries. When `asRoot` is set on a
   *            directory entry, the entry IS the synthetic root: its
   *            children are walked with an empty path prefix and the
   *            entry itself is NOT pushed (it would otherwise show as
   *            a redundant subfolder under the renderer's `📁 <name>`
   *            header — see contract above).
   *          - `{ file: File, path?: string }` — pre-collected leaf;
   *            `path` is taken verbatim (root-relative, no leading
   *            slash, no leading root name).
   *        When neither `path` nor `asRoot` is present, the entry's
   *        bare `entry.name` (or `file.name`) is used — i.e. it is
   *        placed at the top level of the synthetic root.
   * @returns {Promise<{folder: FolderFile, truncated: boolean,
   *                    walkedCount: number}>}
   */
  static async fromEntries(rootName, sources) {
    const cap = (typeof PARSER_LIMITS !== 'undefined'
                 && PARSER_LIMITS && PARSER_LIMITS.MAX_FOLDER_ENTRIES) || 4096;
    const flat = [];
    let truncated = false;
    let walkedCount = 0;

    const pushDir = (path) => {
      if (flat.length >= cap) { truncated = true; return false; }
      flat.push({ path, dir: true, size: 0 });
      walkedCount++;
      return true;
    };
    const pushFile = (path, file) => {
      if (flat.length >= cap) { truncated = true; return false; }
      flat.push({
        path,
        dir: false,
        size: (file && Number.isFinite(file.size)) ? file.size : 0,
        file,
        mtime: (file && file.lastModified) ? new Date(file.lastModified) : null,
      });
      walkedCount++;
      return true;
    };

    // Recursive directory walker for FileSystemDirectoryEntry. The API is
    // callback-based; readEntries is NOT guaranteed to return all children
    // in a single call — we loop until it returns an empty array.
    // `prefix` is the root-relative path of `dirEntry`'s parent context;
    // an empty string means "walk the synthetic root's children at depth 1".
    const walkDir = async (dirEntry, prefix) => {
      const reader = dirEntry.createReader();
      // BFS-style: read in batches until exhausted. Cap the inner loop
      // defensively at 1024 iterations (an obscenely deep folder would
      // hit `cap` first — this is just a paranoia guard against a
      // pathological browser implementation that never returns []).
      for (let guard = 0; guard < 1024; guard++) {
        if (flat.length >= cap) { truncated = true; return; }
        const batch = await new Promise((resolve, reject) => {
          reader.readEntries((entries) => resolve(entries), (err) => reject(err));
        });
        if (!batch || batch.length === 0) return;
        for (const child of batch) {
          if (flat.length >= cap) { truncated = true; return; }
          const childPath = prefix ? prefix + '/' + child.name : child.name;
          if (child.isDirectory) {
            if (!pushDir(childPath)) return;
            await walkDir(child, childPath);
          } else if (child.isFile) {
            const file = await new Promise((resolve, reject) => {
              child.file((f) => resolve(f), (err) => reject(err));
            });
            if (!pushFile(childPath, file)) return;
          }
        }
      }
    };

    for (const src of (sources || [])) {
      if (flat.length >= cap) { truncated = true; break; }
      if (src && src.entry) {
        const entry = src.entry;
        // `asRoot` on a directory entry: the entry IS the synthetic root,
        // so we walk its children with an empty prefix and do NOT push
        // the directory itself. Without this branch, a single-folder drop
        // produces a redundant top-level subfolder mirroring the root
        // (e.g. `forensics → forensics → file.txt`).
        if (src.asRoot && entry.isDirectory) {
          try { await walkDir(entry, ''); }
          catch (e) {
            // eslint-disable-next-line no-console
            console.warn('FolderFile: root walk failed for', entry.name, e);
            truncated = true;
          }
          continue;
        }
        // Otherwise the entry sits one tier under the synthetic root.
        // Default its path to its bare name (no `rootName` prefix — the
        // synthetic root carries that label in the renderer header).
        const relPath = (src.path || entry.name || '').replace(/^\/+/, '');
        if (entry.isDirectory) {
          if (!pushDir(relPath)) break;
          try { await walkDir(entry, relPath); }
          catch (e) {
            // A single failed directory shouldn't kill the whole ingest.
            // Surface as a synthetic IOC.INFO row at render time via the
            // truncated flag — the caller already pushes one when truncated.
            // eslint-disable-next-line no-console
            console.warn('FolderFile: directory walk failed for', relPath, e);
            truncated = true;
          }
        } else if (entry.isFile) {
          try {
            const file = await new Promise((resolve, reject) => {
              entry.file((f) => resolve(f), (err) => reject(err));
            });
            if (!pushFile(relPath, file)) break;
          } catch (e) {
            // eslint-disable-next-line no-console
            console.warn('FolderFile: file read failed for', relPath, e);
            truncated = true;
          }
        }
      } else if (src && src.file) {
        // Caller is responsible for picking a root-relative path. Default
        // to the bare file name (top-level of the synthetic root).
        const path = (src.path || src.file.name || '').replace(/^\/+/, '');
        if (!pushFile(path, src.file)) break;
      }
    }

    return {
      folder: new FolderFile(rootName, flat),
      truncated,
      walkedCount,
    };
  }
}

if (typeof window !== 'undefined') window.FolderFile = FolderFile;
