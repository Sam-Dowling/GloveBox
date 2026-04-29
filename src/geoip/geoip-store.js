'use strict';
// ════════════════════════════════════════════════════════════════════════════
// geoip-store.js — IndexedDB persistence for the user-uploaded MMDB.
//
// localStorage is the canonical chokepoint for every other persistence
// surface in Loupe (`safeStorage` in `src/storage.js`). MMDB files are
// 8–80 MB, well past the 5 MB localStorage quota every browser caps at,
// so this is the one preference that has to live in IndexedDB instead.
//
// Surface — mirrors the safeStorage idiom (best-effort, never throws,
// silent on quota / blocked storage):
//
//   await GeoipStore.save(blob, meta)  → bool
//   await GeoipStore.load()            → { blob, meta } | null
//   await GeoipStore.clear()           → bool
//   await GeoipStore.getMeta()         → meta | null
//
// `meta` is a plain JSON object the caller chooses (we suggest
// `{ filename, size, savedAt, vintage, databaseType }`); the store
// never inspects it.
//
// Database / store shape:
//   • DB name: `loupe-geoip`
//   • Version: 1
//   • Object store: `db` (out-of-line keys; we use the literal key 'mmdb'
//     for the single-blob slot — version 2 of this module could store
//     multiple uploaded providers without a migration if we ever want
//     country + city + ASN as separate slots).
//
// Quota / failure modes — IndexedDB writes can fail on:
//   • Private-mode browsers (Firefox in 2024+: writes succeed but the DB
//     is wiped on tab close — caller sees the next `load()` return null)
//   • Quota exhaustion (Safari has aggressive eviction)
//   • Disabled-storage policies
// All four save/load/clear/getMeta methods catch every IndexedDB error
// path and return `false` / `null` rather than throwing — the Settings
// dialog renders "Could not save (storage blocked or full)" toasts on
// the boolean.
// ════════════════════════════════════════════════════════════════════════════

const GeoipStore = (function () {
  const DB_NAME = 'loupe-geoip';
  const DB_VERSION = 1;
  const STORE = 'db';
  const KEY_BLOB = 'mmdb';
  const KEY_META = 'mmdb-meta';

  function _hasIDB() {
    try { return typeof indexedDB !== 'undefined' && indexedDB; }
    catch (_) { return false; }
  }

  // Open the database, creating the object store on first run. Returns a
  // Promise that resolves to an IDBDatabase (or rejects on the genuine
  // "blocked / disabled" cases — caller wraps in try/catch).
  function _openDB() {
    return new Promise((resolve, reject) => {
      if (!_hasIDB()) { reject(new Error('IndexedDB unavailable')); return; }
      let req;
      try { req = indexedDB.open(DB_NAME, DB_VERSION); }
      catch (e) { reject(e); return; }
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE)) {
          db.createObjectStore(STORE);   // out-of-line keys
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error || new Error('open failed'));
      req.onblocked = () => reject(new Error('open blocked'));
    });
  }

  // Tiny `tx → request → promise` adapter. Every IDB operation is a
  // request inside a transaction; the transaction itself completes
  // separately from the request, so we have to wire BOTH `oncomplete`
  // (for writes) AND `request.onsuccess` (for reads) to be safe.
  function _runTx(db, mode, fn) {
    return new Promise((resolve, reject) => {
      let tx;
      try { tx = db.transaction(STORE, mode); }
      catch (e) { reject(e); return; }
      const store = tx.objectStore(STORE);
      let result;
      tx.oncomplete = () => resolve(result);
      tx.onabort = () => reject(tx.error || new Error('tx aborted'));
      tx.onerror = () => reject(tx.error || new Error('tx error'));
      try {
        const req = fn(store);
        if (req) req.onsuccess = () => { result = req.result; };
      } catch (e) { reject(e); }
    });
  }

  return {
    /** Persist the supplied Blob + meta object. Returns true on success
     *  (transaction completed), false on any IDB error path. */
    async save(blob, meta) {
      if (!blob) return false;
      let db;
      try { db = await _openDB(); }
      catch (_) { return false; }
      try {
        await _runTx(db, 'readwrite', (s) => {
          s.put(blob, KEY_BLOB);
          // Stamp the metadata together with the blob in the same
          // transaction so a partial save (one row written, the other
          // not) can never leave a Blob without its provenance.
          s.put(meta || {}, KEY_META);
          return null;
        });
        return true;
      } catch (_) { return false; }
      finally { try { db.close(); } catch (_) { /* noop */ } }
    },

    /** Returns `{ blob, meta }` or null on miss / IDB failure. The
     *  Blob keeps its original MIME type (typically empty / octet-
     *  stream — the caller pipes it straight into MmdbReader.fromBlob). */
    async load() {
      let db;
      try { db = await _openDB(); }
      catch (_) { return null; }
      try {
        let blob = null, meta = null;
        await _runTx(db, 'readonly', (s) => {
          const r1 = s.get(KEY_BLOB);
          r1.onsuccess = () => { blob = r1.result || null; };
          const r2 = s.get(KEY_META);
          r2.onsuccess = () => { meta = r2.result || null; };
          return null;
        });
        if (!blob) return null;
        return { blob, meta };
      } catch (_) { return null; }
      finally { try { db.close(); } catch (_) { /* noop */ } }
    },

    /** Cheap meta-only fetch — used by Settings to render the "currently
     *  loaded" panel without paying the full Blob deserialisation cost. */
    async getMeta() {
      let db;
      try { db = await _openDB(); }
      catch (_) { return null; }
      try {
        let meta = null;
        await _runTx(db, 'readonly', (s) => {
          const r = s.get(KEY_META);
          r.onsuccess = () => { meta = r.result || null; };
          return null;
        });
        return meta;
      } catch (_) { return null; }
      finally { try { db.close(); } catch (_) { /* noop */ } }
    },

    /** Drop both rows. Returns true on success. */
    async clear() {
      let db;
      try { db = await _openDB(); }
      catch (_) { return false; }
      try {
        await _runTx(db, 'readwrite', (s) => {
          s.delete(KEY_BLOB);
          s.delete(KEY_META);
          return null;
        });
        return true;
      } catch (_) { return false; }
      finally { try { db.close(); } catch (_) { /* noop */ } }
    },
  };
})();

// Mirror the FileDownload / SandboxPreview / safeStorage pattern — expose
// a single global so every module gets the same singleton without an
// import path. CommonJS export kept for the unit-test harness.
if (typeof window !== 'undefined') {
  window.GeoipStore = GeoipStore;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { GeoipStore };
}
