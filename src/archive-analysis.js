'use strict';
// ════════════════════════════════════════════════════════════════════════════
// archive-analysis.js — shared security analysis for archive renderers.
//
// Loaded before every archive renderer (zip / rar / 7z / cab). Owns the
// canonical classifier sets and the Zip-Slip / Tar-Slip traversal detector
// so per-format renderers produce identical warnings for identical
// suspicious inputs. Prior to this helper, each renderer had its own
// EXEC_EXTS / DECOY_EXTS set and its own traversal check, which had
// already drifted:
//
//   • ZIP used a strict `_findTraversalEntries` that recognised `..` as a
//     segment (rejecting `foo..bar.txt`) and flagged tar symlink targets.
//   • RAR / 7z / CAB used a weak `p.includes('../') || ...` substring
//     check that false-positives on names with `..` in the middle AND
//     misses UNC / drive-letter prefixes with forward slashes.
//
//   • ZIP's EXEC_EXTS omitted `sys`, `so`, `dylib` — the other three
//     formats listed them.
//
// The helper closes both gaps without changing per-renderer callsites
// that already had richer local data (e.g. ZIP's own app-bundle
// detection). Renderers keep their own `static EXEC_EXTS = ArchiveAnalysis.EXEC_EXTS`
// alias so existing `RarRenderer.EXEC_EXTS.has(...)` call sites keep
// working identically.
// ════════════════════════════════════════════════════════════════════════════
const ArchiveAnalysis = Object.freeze({
  // Canonical executable / script extension set. Matches the richest
  // historical per-renderer union (RAR / 7z / CAB) — ZIP formerly
  // omitted `sys`, `so`, `dylib` but those are equally dangerous
  // inside ZIP wrappers.
  EXEC_EXTS: Object.freeze(new Set([
    'exe', 'dll', 'scr', 'com', 'pif', 'cpl', 'msi', 'msp', 'mst', 'sys',
    'bat', 'cmd', 'ps1', 'psm1', 'psd1', 'vbs', 'vbe', 'js', 'jse',
    'wsf', 'wsh', 'wsc', 'hta', 'lnk', 'inf', 'reg', 'sct',
    'jar', 'py', 'rb', 'sh', 'bash', 'so', 'dylib',
    'docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm', 'ppam', 'xlam',
  ])),

  // Decoy extensions used in double-extension social-engineering
  // (e.g. `invoice.pdf.exe`, `photo.jpg.scr`).
  DECOY_EXTS: Object.freeze(new Set([
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'jpg', 'png', 'gif', 'txt', 'rtf',
  ])),

  // Nested archive extension regex — flagged as a medium warning in
  // every archive format so analysts can drill down.
  NESTED_ARCHIVE_RE: /\.(zip|rar|7z|cab|gz|tar|iso|img)$/i,

  /**
   * Return the trailing extension of a path, lower-cased. Never throws.
   */
  extOf(path) {
    const p = String(path || '');
    const name = p.split('/').pop();
    const dot = name.lastIndexOf('.');
    if (dot < 0) return '';
    return name.slice(dot + 1).toLowerCase();
  },

  /**
   * True iff the path looks like a double-extension decoy: three or
   * more `.`-separated segments where the trailing segment is an
   * executable and the penultimate segment is a decoy extension.
   *
   * Examples flagged: `invoice.pdf.exe`, `report.docx.vbs`.
   * Examples NOT flagged: `archive.tar.gz` (`.gz` is not in EXEC_EXTS),
   * `.gitignore` (no penultimate segment), `foo.exe` (only two
   * segments).
   */
  isDoubleExt(path) {
    const name = String(path || '').split('/').pop();
    const parts = name.split('.');
    if (parts.length < 3) return false;
    const last = parts[parts.length - 1].toLowerCase();
    const prev = parts[parts.length - 2].toLowerCase();
    return ArchiveAnalysis.EXEC_EXTS.has(last)
        && ArchiveAnalysis.DECOY_EXTS.has(prev);
  },

  /**
   * Strict Zip-Slip / Tar-Slip detector. Same logic originally shipped
   * in `ZipRenderer._findTraversalEntries` — the weaker
   * `p.includes('../')` substring check used by RAR / 7z / CAB
   * false-positives on names like `foo..bar.txt` and misses
   * drive-letter prefixes that use forward slashes (`C:/evil`).
   *
   * Recognises three escape classes:
   *   - 'parent-traversal'  literal `..` segment post-slash-normalise
   *                         (`../etc/passwd`, `foo/../../bar`, `..\\evil`)
   *   - 'absolute-path'     leading `/`, `\`, `\\` (UNC), or drive-letter
   *                         prefix (`C:\…` or `C:/…`)
   *   - 'symlink-traversal' tar entry whose `linkName` itself escapes
   *                         (absolute or contains `..` segment)
   *
   * @param {Array<{path?:string,name?:string,linkName?:string}>} entries
   * @returns {Array<{path:string,kind:string,target?:string}>}
   */
  findTraversalEntries(entries) {
    const hits = [];
    for (const e of entries || []) {
      const rawPath = e.path || e.name || '';
      const p = rawPath.replace(/\\/g, '/');
      // Absolute paths — Unix, UNC, or drive-letter prefixed.
      if (rawPath.startsWith('/') || rawPath.startsWith('\\') || /^[A-Za-z]:[\\/]/.test(rawPath)) {
        hits.push({ path: rawPath, kind: 'absolute-path' });
        continue;
      }
      // Parent-dir segment (avoids matching e.g. `foo..bar.txt`).
      if (p === '..' || p.startsWith('../') || p.endsWith('/..') || p.includes('/../')) {
        hits.push({ path: rawPath, kind: 'parent-traversal' });
        continue;
      }
      // Tar symlink targets — the `linkName` itself may escape even if
      // the entry's own path is benign.
      const ln = e.linkName;
      if (ln) {
        const lnNorm = String(ln).replace(/\\/g, '/');
        const lnAbs = ln.startsWith('/') || /^[A-Za-z]:[\\/]/.test(ln);
        const lnEscape = lnAbs
          || lnNorm === '..' || lnNorm.startsWith('../')
          || lnNorm.endsWith('/..') || lnNorm.includes('/../');
        if (lnEscape) {
          hits.push({ path: rawPath, kind: 'symlink-traversal', target: ln });
        }
      }
    }
    return hits;
  },

  /**
   * Build the shared warning set every archive renderer emits at the
   * top of its `_checkWarnings`. Returns an array of
   * `{ sev, msg }` records that the caller appends to its own
   * format-specific warning list.
   *
   * `entries` is the normalised entry list. Each entry should look
   * like `{ path, isDir?, linkName?, special? }`. `kind` is the
   * human-readable archive label used in messages (e.g. `'archive'`,
   * `'cabinet'`, `'disk image'`).
   */
  buildCommonWarnings(entries, opts) {
    const kind = (opts && opts.kind) || 'archive';
    const files = (entries || []).filter(e => !e.isDir);
    const w = [];

    const execs = files.filter(e => ArchiveAnalysis.EXEC_EXTS.has(ArchiveAnalysis.extOf(e.path || e.name)));
    if (execs.length) {
      const sample = execs.slice(0, 5).map(e => (e.path || e.name || '').split('/').pop()).join(', ');
      w.push({
        sev: 'high',
        msg: `⚠ ${execs.length} executable/script file(s): ${sample}${execs.length > 5 ? ' …' : ''}`,
      });
    }

    const doubles = files.filter(e => ArchiveAnalysis.isDoubleExt(e.path || e.name || ''));
    if (doubles.length) {
      const sample = doubles.slice(0, 3).map(e => (e.path || e.name || '').split('/').pop()).join(', ');
      w.push({
        sev: 'high',
        msg: `⚠ Double-extension file(s) detected: ${sample}${doubles.length > 3 ? ' …' : ''}`,
      });
    }

    const nested = files.filter(e => ArchiveAnalysis.NESTED_ARCHIVE_RE.test(e.path || e.name || ''));
    if (nested.length) {
      const sample = nested.slice(0, 3).map(e => (e.path || e.name || '').split('/').pop()).join(', ');
      w.push({
        sev: 'medium',
        msg: `📦 Nested archive(s): ${sample}`,
      });
    }

    const htas = files.filter(e => /\.hta$/i.test(e.path || e.name || ''));
    if (htas.length) {
      w.push({ sev: 'high', msg: `⚠ HTA file(s) — can execute arbitrary scripts` });
    }

    const lnks = files.filter(e => /\.lnk$/i.test(e.path || e.name || ''));
    if (lnks.length) {
      w.push({ sev: 'high', msg: `⚠ Windows shortcut (.lnk) file(s) — common phishing technique` });
    }

    const traversal = ArchiveAnalysis.findTraversalEntries(entries);
    if (traversal.length) {
      const samplePaths = traversal.slice(0, 3).map(t => t.path).join(', ');
      const more = traversal.length > 3 ? ' …' : '';
      w.push({
        sev: 'high',
        msg: `⚠ Zip Slip / Tar Slip — ${traversal.length} entry/entries escape the ${kind} root: ${samplePaths}${more}`,
      });
    }

    return w;
  },
});
