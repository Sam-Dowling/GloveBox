// nicelist-user.js — User-defined nicelists (custom "known-good" lists)
//
// Sits on top of the built-in `NICELIST` / `isNicelisted` in nicelist.js.
// Loads AFTER nicelist.js in JS_FILES so the sidebar can still call
// `isNicelisted(...)` unchanged for the Default Nicelist, then fall back
// to `_NicelistUser.match(...)` for any customer-supplied lists (MDR
// customer domains, employee email addresses, on-network asset hosts,
// etc.).
//
// Design constraints (must stay true to Loupe's architecture):
//   • No regex / no globs. Same "exact host OR subdomain" semantics as
//     the built-in list so one mental model covers both surfaces.
//   • Pure IOC presentation. Never suppresses YARA detections. Only
//     affects URL / Domain / Hostname / Email rows in the IOC table.
//   • localStorage-only persistence (single key). No network, no file
//     system, no cookies. Read / write is budget-guarded.
//   • No vendor deps — pure string + JSON.
//
// Persistence keys (both `loupe_`-prefixed):
//   • loupe_nicelists_user         — JSON: { version: 1, lists: [ … ] }
//   • loupe_nicelist_builtin_enabled — "0" | "1" (owned by nicelist.js,
//                                      exposed here for the Settings UI)
//
// Per-list shape:
//   {
//     id:        "nl_<base36>",   // stable, used for delete-by-id
//     name:      "Acme domains",  // user-editable, ≤ 80 chars, plain text
//     enabled:   true,
//     createdAt: 1713640000000,
//     updatedAt: 1713640000000,
//     entries:   ["acme.com", "acme.co.uk", "corp.acme.com"]
//   }
//
// Soft caps (so a runaway paste can't blow the 5 MB localStorage quota):
//   • Max 64 user lists
//   • Max 10,000 entries per list
//   • Max 25,000 entries across all lists in a single bulk import (M5)
//   • Max 1 MB serialised JSON for the whole blob
// On overflow we refuse the write and surface a console warning; the UI
// layer shows a toast. The previous stored blob is never mutated on an
// overflow write, so the user cannot corrupt their lists by pasting too
// much.
//
// Read-side robustness (M5): a corrupt `loupe_nicelists_user` blob (manually
// edited, partially written by a crashed tab, …) used to silently masquerade
// as "no user lists at all". `_loadRaw` now distinguishes "absent" from
// "present-but-corrupt" and on corruption (a) emits a single console warning
// and (b) clears the bad key so subsequent reads start clean instead of
// repeatedly tripping over the same poisoned blob. The warning is intentionally
// console-only — the Settings UI surfaces a parallel banner via
// `lastReadError()` when the user opens the Nicelists tab.

(function (global) {
  'use strict';

  const STORAGE_KEY = 'loupe_nicelists_user';
  const BUILTIN_ENABLED_KEY = 'loupe_nicelist_builtin_enabled';

  const MAX_LISTS = 64;
  const MAX_ENTRIES_PER_LIST = 10000;
  const MAX_NAME_LEN = 80;
  const MAX_BLOB_BYTES = 1024 * 1024;
  // M5 — bulk-import aggregate cap. A single `importAll(text, …)` call
  // pulling in more than this many normalised entries (summed across every
  // incoming list) is refused before the first write, to keep an "I dropped
  // the wrong file" mistake from overwriting a healthy local store with
  // 200k typo'd lines that then trip MAX_BLOB_BYTES on the next save.
  const MAX_IMPORT_ENTRIES = 25000;

  // ── M5 — read-side parse-failure tracking ────────────────────────────
  // `safeStorage.getJSON` swallows parse failures (returns null) so a
  // genuinely-corrupt blob is indistinguishable from "key absent". We
  // re-do the read here using `safeStorage.get` + manual JSON.parse so we
  // can latch the failure into `_lastReadError` and clear the bad key.
  // Settings UI surfaces this through `lastReadError()` to show a banner.
  let _lastReadError = '';

  // ── tiny utils ─────────────────────────────────────────────────────────

  function _newId() {
    const rand = Math.random().toString(36).slice(2, 10);
    return 'nl_' + Date.now().toString(36) + rand;
  }

  function _nowMs() { return Date.now(); }

  function _sanitiseName(raw) {
    let s = String(raw == null ? '' : raw);
    // Strip control chars + collapse whitespace, no HTML allowed at all.
    s = s.replace(/[\u0000-\u001F\u007F<>]/g, '').replace(/\s+/g, ' ').trim();
    if (!s) s = 'Untitled list';
    if (s.length > MAX_NAME_LEN) s = s.slice(0, MAX_NAME_LEN);
    return s;
  }

  // Accept bare hostnames, domains, emails, or full URLs. Normalise to
  // the host-or-email form the matcher expects. Returns '' if the input
  // can't be interpreted as a usable entry (keeps the paste surface
  // forgiving without silently expanding coverage).
  function _normaliseEntry(raw) {
    if (raw == null) return '';
    let s = String(raw).trim();
    if (!s) return '';

    // Strip surrounding quotes / brackets (CSV / spreadsheet exports)
    s = s.replace(/^["'`\[(]+|["'`\])]+$/g, '').trim();
    if (!s) return '';

    // Refang: turn `example[.]com` → `example.com`, `example[dot]com` →
    // same. Keeps pasting threat-intel reports ergonomic.
    s = s.replace(/\[\.\]/g, '.').replace(/\[dot\]/gi, '.');
    s = s.replace(/\[@\]/g, '@').replace(/\[at\]/gi, '@');
    s = s.replace(/\bhxxp(s?):/gi, 'http$1:');

    // Email?
    const atIdx = s.lastIndexOf('@');
    if (atIdx > 0 && atIdx < s.length - 1 && s.indexOf(' ') < 0) {
      // Validate minimally: the domain side must look domain-y.
      const local = s.slice(0, atIdx);
      const domain = s.slice(atIdx + 1).toLowerCase();
      if (/^[a-z0-9._-]+$/i.test(local) && /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain)) {
        return local + '@' + domain;
      }
    }

    // URL?  Strip scheme + path down to the host.
    const urlMatch = s.match(/^[a-zA-Z][a-zA-Z0-9+.\-]*:\/\/([^/?#\s]+)/);
    if (urlMatch) s = urlMatch[1];

    // Strip userinfo + port.
    const at = s.lastIndexOf('@');
    if (at >= 0) s = s.slice(at + 1);
    const colon = s.lastIndexOf(':');
    if (colon >= 0 && s.indexOf(']') < colon) s = s.slice(0, colon);
    if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);

    s = s.toLowerCase();

    // Must look like a hostname. No wildcards, no regex.
    if (!/^[a-z0-9.-]+$/.test(s)) return '';
    // Must have at least one dot AND a sensible TLD-ish tail. Drops
    // pure localhost / single-label noise that would match too broadly.
    if (!/\.[a-z]{2,}$/.test(s)) return '';
    // Reject leading / trailing / doubled dots.
    if (s.startsWith('.') || s.endsWith('.') || s.indexOf('..') >= 0) return '';
    return s;
  }

  function _dedupSorted(arr) {
    const seen = new Set();
    const out = [];
    for (const e of arr) {
      const v = _normaliseEntry(e);
      if (!v || seen.has(v)) continue;
      seen.add(v);
      out.push(v);
    }
    out.sort();
    if (out.length > MAX_ENTRIES_PER_LIST) out.length = MAX_ENTRIES_PER_LIST;
    return out;
  }

  // ── storage ────────────────────────────────────────────────────────────

  function _loadRaw() {
    // Hand-roll the read so we can distinguish "absent" (return null cleanly)
    // from "present-but-corrupt" (latch `_lastReadError`, clear the bad key,
    // and return null). `safeStorage.getJSON` collapses both into null and
    // would silently drop the user's lists on every page load if a single
    // bad write got through. See header — M5.
    const raw = safeStorage.get(STORAGE_KEY);
    if (raw == null || raw === '') { _lastReadError = ''; return null; }
    let j;
    try { j = JSON.parse(raw); }
    catch (e) {
      _lastReadError =
        'Stored nicelists blob is corrupt JSON — your saved lists could not be ' +
        'loaded and the bad blob has been cleared. Re-import from a backup if you ' +
        'have one.';
       
      console.warn('[nicelist-user] corrupt blob; clearing key:', e && e.message);
      // Clear the poisoned key so we don't repeat this work + warning every
      // load. The user has already lost the data — keeping the bad blob
      // around just makes the failure mode permanent.
      try { safeStorage.remove(STORAGE_KEY); } catch (_) { /* best-effort */ }
      return null;
    }
    if (!j || typeof j !== 'object' || !Array.isArray(j.lists)) {
      // Shape is wrong but JSON parsed — treat as absent without warning;
      // most likely an older / unrelated key value, not a corruption event.
      _lastReadError = '';
      return null;
    }
    _lastReadError = '';
    return j;
  }

  /**
   * Surface the most recent read-side parse-failure message (M5). Settings
   * UI calls this when rendering the Nicelists tab to show a banner.
   * Returns '' when the last read was clean.
   */
  function lastReadError() { return _lastReadError; }

  function _saveRaw(blob) {
    let s;
    try { s = JSON.stringify(blob); }
    catch (_) { return false; }
    if (s.length > MAX_BLOB_BYTES) {
       
      console.warn('[nicelist-user] refusing to save: blob exceeds 1 MB cap (' + s.length + ' bytes)');
      return false;
    }
    if (!safeStorage.set(STORAGE_KEY, s)) {
       
      console.warn('[nicelist-user] save failed: storage write rejected');
      return false;
    }
    return true;
  }

  function _normaliseList(l) {
    if (!l || typeof l !== 'object') return null;
    const id = (typeof l.id === 'string' && l.id.startsWith('nl_')) ? l.id : _newId();
    const name = _sanitiseName(l.name || 'Untitled list');
    const enabled = l.enabled !== false;
    const entries = Array.isArray(l.entries) ? _dedupSorted(l.entries) : [];
    const createdAt = Number.isFinite(l.createdAt) ? l.createdAt : _nowMs();
    const updatedAt = Number.isFinite(l.updatedAt) ? l.updatedAt : createdAt;
    return { id, name, enabled, createdAt, updatedAt, entries };
  }

  // ── public API ─────────────────────────────────────────────────────────

  /** Load all user lists (normalised). Never throws. */
  function load() {
    const raw = _loadRaw();
    if (!raw) return [];
    const out = [];
    for (const l of raw.lists) {
      const n = _normaliseList(l);
      if (n) out.push(n);
      if (out.length >= MAX_LISTS) break;
    }
    return out;
  }

  /** Overwrite all user lists. Returns true on success, false on overflow. */
  function save(lists) {
    const safe = (Array.isArray(lists) ? lists : [])
      .map(_normaliseList)
      .filter(Boolean)
      .slice(0, MAX_LISTS);
    return _saveRaw({ version: 1, lists: safe });
  }

  /** Create a new empty list, persist it, return the new record. */
  function createList(name) {
    const lists = load();
    if (lists.length >= MAX_LISTS) return null;
    const rec = _normaliseList({
      id: _newId(),
      name: _sanitiseName(name || 'New nicelist'),
      enabled: true,
      createdAt: _nowMs(),
      updatedAt: _nowMs(),
      entries: [],
    });
    lists.push(rec);
    return save(lists) ? rec : null;
  }

  /** Delete one list by id. Returns true if removed. */
  function deleteList(id) {
    const lists = load();
    const before = lists.length;
    const filtered = lists.filter(l => l.id !== id);
    if (filtered.length === before) return false;
    return save(filtered);
  }

  /** Shallow-patch a list (id required). Returns the updated record. */
  function updateList(id, patch) {
    const lists = load();
    const idx = lists.findIndex(l => l.id === id);
    if (idx < 0) return null;
    const cur = lists[idx];
    const next = _normaliseList({
      id: cur.id,
      name: patch && patch.name != null ? patch.name : cur.name,
      enabled: patch && patch.enabled != null ? !!patch.enabled : cur.enabled,
      entries: patch && patch.entries ? patch.entries : cur.entries,
      createdAt: cur.createdAt,
      updatedAt: _nowMs(),
    });
    lists[idx] = next;
    return save(lists) ? next : null;
  }

  /** Add one entry to a list. Returns the updated record or null. */
  function addEntry(id, entry) {
    const lists = load();
    const idx = lists.findIndex(l => l.id === id);
    if (idx < 0) return null;
    const normalised = _normaliseEntry(entry);
    if (!normalised) return null;
    const entries = lists[idx].entries.slice();
    if (entries.indexOf(normalised) >= 0) return lists[idx]; // no-op
    entries.push(normalised);
    return updateList(id, { entries });
  }

  /** Remove one entry from a list. */
  function removeEntry(id, entry) {
    const lists = load();
    const idx = lists.findIndex(l => l.id === id);
    if (idx < 0) return null;
    const entries = lists[idx].entries.filter(e => e !== entry);
    return updateList(id, { entries });
  }

  // ── matching ───────────────────────────────────────────────────────────

  // Same label-boundary semantics as `_nicelistHostMatches` in nicelist.js,
  // but reads from the user-supplied lists instead of the frozen built-in.
  function _hostMatches(host, entries) {
    if (!host || !entries || !entries.length) return false;
    const h = String(host).toLowerCase();
    for (const entry of entries) {
      if (!entry || entry.indexOf('@') >= 0) continue;   // skip email rows
      if (h === entry) return true;
      if (h.length > entry.length && h.endsWith('.' + entry)) return true;
    }
    return false;
  }

  function _emailMatches(email, entries) {
    if (!email || !entries || !entries.length) return false;
    // Unwrap RFC-5322 display-name form: `Bob Smith <bob@example.com>` →
    // `bob@example.com`. Without this an `example.com` entry fails to
    // match and the full-address compare `entry === e` sees a trailing
    // `>` on the input.
    let e = String(email).toLowerCase();
    const lt = e.lastIndexOf('<');
    const gt = e.lastIndexOf('>');
    if (lt >= 0 && gt > lt) e = e.slice(lt + 1, gt);
    const at = e.lastIndexOf('@');
    if (at < 0) return false;
    // Strip any trailing junk off the host (quoted-printable artefacts,
    // stray punctuation) before comparing.
    const domain = e.slice(at + 1).replace(/[^a-z0-9.-].*$/, '');
    for (const entry of entries) {
      if (!entry) continue;
      // Full-address match
      if (entry.indexOf('@') >= 0 && entry === e) return true;
      // Domain-suffix match (entry is a host)
      if (entry.indexOf('@') < 0) {
        if (domain === entry) return true;
        if (domain.length > entry.length && domain.endsWith('.' + entry)) return true;
      }
    }
    return false;
  }

  function _hostFromUrl(url) {
    const s = String(url || '').trim();
    const m = s.match(/^[a-zA-Z][a-zA-Z0-9+.\-]*:\/\/([^/?#]+)/);
    if (!m) return '';
    let host = m[1];
    const at = host.lastIndexOf('@');
    if (at >= 0) host = host.slice(at + 1);
    const colon = host.lastIndexOf(':');
    if (colon >= 0 && host.indexOf(']') < colon) host = host.slice(0, colon);
    if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
    return host.toLowerCase();
  }

  /**
   * Is `value` (of IOC type `type`) matched by ANY enabled user list?
   * Returns the matching list's display name, or null.
   *
   * Cached per-render: the sidebar calls this once per IOC row, so we
   * snapshot `load()` the first time it's called inside a tick and
   * invalidate the snapshot on every mutation (create/delete/update).
   */
  let _cache = null;
  function _getCache() {
    if (_cache) return _cache;
    _cache = load().filter(l => l && l.enabled);
    return _cache;
  }
  function _invalidate() { _cache = null; }

  function match(value, type) {
    if (!value || !type) return null;
    const lists = _getCache();
    if (!lists.length) return null;
    const v = String(value).trim();
    if (!v) return null;

    for (const l of lists) {
      const entries = l.entries;
      if (!entries || !entries.length) continue;
      let hit = false;
      switch (type) {
        case 'URL': {
          const host = _hostFromUrl(v);
          if (host && _hostMatches(host, entries)) hit = true;
          break;
        }
        case 'Domain':
        case 'Hostname':
          hit = _hostMatches(v.toLowerCase(), entries);
          break;
        case 'Email':
          hit = _emailMatches(v.toLowerCase(), entries);
          break;
        default:
          break;
      }
      if (hit) return l.name;
    }
    return null;
  }

  // Wrap every mutation so the render cache stays fresh without callers
  // having to remember.
  const _wrapInvalidate = fn => function wrapped() {
    const result = fn.apply(null, arguments);
    _invalidate();
    return result;
  };
  const saveWrapped = _wrapInvalidate(save);
  const createWrapped = _wrapInvalidate(createList);
  const deleteWrapped = _wrapInvalidate(deleteList);
  const updateWrapped = _wrapInvalidate(updateList);
  const addEntryWrapped = _wrapInvalidate(addEntry);
  const removeEntryWrapped = _wrapInvalidate(removeEntry);

  // ── parse (CSV / JSON / TXT) ───────────────────────────────────────────
  //
  // Used by the Import button in the Settings "Nicelists" tab. Autodetects
  // format. Returns `{ name, entries }` so the caller can fold the name in
  // from the source filename when the blob itself is nameless.
  function parse(text, filenameHint) {
    const src = String(text || '');
    if (!src) return { name: '', entries: [] };

    // JSON?  Accept shapes we produced ourselves plus common community
    // list formats (bare array, `{ entries: [...] }`, `{ domains: [...] }`
    // and our bulk-export `{ version: 1, lists: [...] }` blob).
    const trimmed = src.trim();
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      try {
        const j = JSON.parse(trimmed);
        if (Array.isArray(j)) {
          return { name: _fileBase(filenameHint), entries: _dedupSorted(j) };
        }
        if (j && typeof j === 'object') {
          // Bulk-export shape — caller should branch on importAll instead,
          // but if a user drops it into single-list import we merge every
          // list's entries and name it after the file.
          if (Array.isArray(j.lists)) {
            const all = [];
            for (const l of j.lists) {
              if (l && Array.isArray(l.entries)) all.push(...l.entries);
            }
            return { name: _fileBase(filenameHint), entries: _dedupSorted(all) };
          }
          const arr = j.entries || j.domains || j.emails || j.values || j.list;
          if (Array.isArray(arr)) {
            return {
              name: _sanitiseName(j.name || _fileBase(filenameHint)),
              entries: _dedupSorted(arr),
            };
          }
        }
      } catch (_) { /* fall through to line-based parsing */ }
    }

    // CSV / TSV / plain text — one entry per line, first column only.
    // Skip comments (# / //), blank lines, and fall back gracefully.
    const lines = src.split(/\r?\n/);
    const raw = [];
    for (const line of lines) {
      let l = line.trim();
      if (!l) continue;
      if (l.startsWith('#') || l.startsWith('//')) continue;
      // Excel-style BOM
      l = l.replace(/^\uFEFF/, '');
      // First column of a comma/semicolon/tab-separated row
      const firstCol = l.split(/[,;\t]/)[0].trim();
      if (firstCol) raw.push(firstCol);
    }
    return { name: _fileBase(filenameHint), entries: _dedupSorted(raw) };
  }

  function _fileBase(name) {
    if (!name) return '';
    const base = String(name).replace(/^.*[\\/]/, '').replace(/\.[^.]+$/, '');
    return _sanitiseName(base || 'Imported list');
  }

  // ── bulk export / import ───────────────────────────────────────────────

  function exportAll() {
    const lists = load();
    return JSON.stringify({
      version: 1,
      kind: 'loupe-nicelists',
      note: 'User-defined nicelists exported from Loupe. Excludes the "Default Nicelist" built-in.',
      exportedAt: new Date().toISOString(),
      lists: lists.map(l => ({
        name: l.name,
        enabled: l.enabled,
        entries: l.entries,
      })),
    }, null, 2);
  }

  function exportList(id) {
    const lists = load();
    const l = lists.find(x => x.id === id);
    if (!l) return null;
    return JSON.stringify({
      version: 1,
      kind: 'loupe-nicelist',
      name: l.name,
      enabled: l.enabled,
      entries: l.entries,
    }, null, 2);
  }

  // mode: 'merge' (default) | 'replace'
  function importAll(text, mode) {
    const src = String(text || '').trim();
    if (!src) return { imported: 0, skipped: 0 };
    let blob;
    try { blob = JSON.parse(src); }
    catch (_) { return { imported: 0, skipped: 0, error: 'not valid JSON' }; }

    // Accept either our bulk-export shape or a bare array of list objects.
    let incoming = [];
    if (Array.isArray(blob)) incoming = blob;
    else if (blob && Array.isArray(blob.lists)) incoming = blob.lists;
    else return { imported: 0, skipped: 0, error: 'no "lists" array found' };

    const normalised = incoming.map(_normaliseList).filter(Boolean);

    // M5 — refuse the import outright if the aggregate entry count is
    // larger than the cap. This guards both the (a) "I dropped the wrong
    // gigabyte CSV" UX accident and (b) the deeper concern that a 200k-row
    // import would hit `MAX_BLOB_BYTES` mid-write and leave the user with
    // a "save succeeded" toast while only a partial blob (or nothing,
    // depending on browser) actually persisted. We bail before the first
    // write so the existing on-disk state is never touched.
    let totalIncoming = 0;
    for (const n of normalised) {
      totalIncoming += (n.entries && n.entries.length) | 0;
      if (totalIncoming > MAX_IMPORT_ENTRIES) break;
    }
    if (totalIncoming > MAX_IMPORT_ENTRIES) {
      return {
        imported: 0,
        skipped: normalised.length,
        error:
          'import refused: aggregate entry count exceeds ' +
          MAX_IMPORT_ENTRIES.toLocaleString() + ' (got ~' +
          totalIncoming.toLocaleString() + '). Split the file into smaller ' +
          'lists and import them separately.',
      };
    }

    if (mode === 'replace') {
      const ok = save(normalised);
      _invalidate();
      return ok
        ? { imported: normalised.length, skipped: 0, replaced: true }
        : { imported: 0, skipped: normalised.length, error: 'storage overflow' };
    }
    // Merge — append, rename-on-collision, skip duplicates by id.
    const existing = load();
    const existingNames = new Set(existing.map(l => l.name));
    const existingIds = new Set(existing.map(l => l.id));
    let added = 0;
    let skipped = 0;
    for (const n of normalised) {
      if (existingIds.has(n.id)) { skipped++; continue; }
      let name = n.name;
      let suffix = 2;
      while (existingNames.has(name)) {
        name = n.name + ' (' + suffix + ')';
        suffix++;
      }
      existing.push(Object.assign({}, n, { id: _newId(), name }));
      existingNames.add(name);
      added++;
      if (existing.length >= MAX_LISTS) break;
    }
    const ok = save(existing);
    _invalidate();
    return ok
      ? { imported: added, skipped, replaced: false }
      : { imported: 0, skipped: added + skipped, error: 'storage overflow' };
  }

  // ── built-in toggle (small API so Settings UI doesn't need to know the
  //    storage key) ──────────────────────────────────────────────────────
  function getBuiltinEnabled() {
    return safeStorage.get(BUILTIN_ENABLED_KEY) !== '0';
  }
  function setBuiltinEnabled(on) {
    safeStorage.set(BUILTIN_ENABLED_KEY, on ? '1' : '0');
  }

  // ── expose ─────────────────────────────────────────────────────────────
  global._NicelistUser = Object.freeze({
    STORAGE_KEY,
    BUILTIN_ENABLED_KEY,
    MAX_LISTS,
    MAX_ENTRIES_PER_LIST,
    MAX_NAME_LEN,
    MAX_IMPORT_ENTRIES,
    load,
    lastReadError,
    save: saveWrapped,
    createList: createWrapped,
    deleteList: deleteWrapped,
    updateList: updateWrapped,
    addEntry: addEntryWrapped,
    removeEntry: removeEntryWrapped,
    match,
    invalidate: _invalidate,
    parse,
    exportAll,
    exportList,
    importAll,
    getBuiltinEnabled,
    setBuiltinEnabled,
    // internal helpers exposed for tests + Settings UI previewing
    _normaliseEntry,
    _sanitiseName,
  });
})(typeof window !== 'undefined' ? window : globalThis);
