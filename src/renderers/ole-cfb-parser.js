'use strict';
// ════════════════════════════════════════════════════════════════════════════
// ole-cfb-parser.js — OLE Compound File Binary (CFB) parser
// Used by: DocBinaryRenderer (.doc), MsgRenderer (.msg), MsiRenderer (.msi)
// No external dependencies.
// ════════════════════════════════════════════════════════════════════════════
class OleCfbParser {
  constructor(buffer) {
    const ab = buffer instanceof ArrayBuffer
      ? buffer
      : buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
    this.buf = new Uint8Array(ab);
    this.dv = new DataView(ab);
    this.streams = new Map();
    this.streamMeta = new Map(); // Metadata-only: {size, start, isMini} without loading content
  }

  parse() {
    const M = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    for (let i = 0; i < 8; i++) if (this.buf[i] !== M[i]) throw new Error('Not an OLE Compound File');
    this._ss = 1 << this.dv.getUint16(0x1E, true);
    this._ms = 1 << this.dv.getUint16(0x20, true);
    this._cut = this.dv.getUint32(0x38, true);
    this._fat = this._buildFAT(this.dv.getUint32(0x2C, true));
    this._mfat = this._buildMFAT(this.dv.getUint32(0x3C, true), this.dv.getUint32(0x40, true));
    this._dir = this._readDir(this.dv.getUint32(0x30, true));
    if (!this._dir.length) throw new Error('OLE: empty directory');
    const root = this._dir[0];
    this._mini = this._chain(root.start, root.size, false);
    if (root.child < 0xFFFFFFF0) this._walk(root.child, '', 0);
    return this;
  }

  /**
   * Lightweight parse that only extracts stream metadata (name, size) without
   * loading stream content into memory. Used by MsiRenderer for large files.
   * Populates this.streamMeta instead of this.streams.
   */
  parseMetadataOnly() {
    const M = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    for (let i = 0; i < 8; i++) if (this.buf[i] !== M[i]) throw new Error('Not an OLE Compound File');
    this._ss = 1 << this.dv.getUint16(0x1E, true);
    this._ms = 1 << this.dv.getUint16(0x20, true);
    this._cut = this.dv.getUint32(0x38, true);
    this._fat = this._buildFAT(this.dv.getUint32(0x2C, true));
    this._mfat = this._buildMFAT(this.dv.getUint32(0x3C, true), this.dv.getUint32(0x40, true));
    this._dir = this._readDir(this.dv.getUint32(0x30, true));
    if (!this._dir.length) throw new Error('OLE: empty directory');
    const root = this._dir[0];
    // Store root info for potential mini-stream loading later
    this._rootStart = root.start;
    this._rootSize = root.size;
    // Walk directory but only collect metadata
    if (root.child < 0xFFFFFFF0) this._walkMetaOnly(root.child, '', 0);
    return this;
  }

  /**
   * Load a specific stream by name (on-demand loading for metadata-only parse).
   * @param {string} name - Stream name (lowercase)
   * @returns {Uint8Array|null} - Stream content or null if not found
   */
  getStream(name) {
    // If already loaded via full parse, return from cache
    if (this.streams.has(name)) return this.streams.get(name);
    // If metadata-only parse, load on demand
    const meta = this.streamMeta.get(name);
    if (!meta) return null;
    // Ensure mini-stream is loaded if needed
    if (meta.isMini && !this._mini) {
      this._mini = this._chain(this._rootStart, this._rootSize, false);
    }
    const data = this._chain(meta.start, meta.size, meta.isMini);
    this.streams.set(name, data); // Cache for future access
    return data;
  }

  _walk(idx, prefix, depth) {
    if (depth > 64 || idx >= 0xFFFFFFF0 || idx >= this._dir.length) return;
    const e = this._dir[idx]; if (!e || e.type === 0) return;
    const path = prefix ? prefix + '/' + e.name : e.name;
    if (e.type === 2) {
      const isMini = e.size > 0 && e.size < this._cut && e.start < 0xFFFFFFF0;
      this.streams.set(path.toLowerCase(), this._chain(e.start, e.size, isMini));
    }
    if (e.type !== 2 && e.child < 0xFFFFFFF0) this._walk(e.child, e.type === 5 ? '' : path, depth + 1);
    if (e.lsib < 0xFFFFFFF0) this._walk(e.lsib, prefix, depth + 1);
    if (e.rsib < 0xFFFFFFF0) this._walk(e.rsib, prefix, depth + 1);
  }

  _walkMetaOnly(idx, prefix, depth) {
    if (depth > 64 || idx >= 0xFFFFFFF0 || idx >= this._dir.length) return;
    const e = this._dir[idx]; if (!e || e.type === 0) return;
    const path = prefix ? prefix + '/' + e.name : e.name;
    if (e.type === 2) {
      const isMini = e.size > 0 && e.size < this._cut && e.start < 0xFFFFFFF0;
      // Store only metadata, don't load content
      this.streamMeta.set(path.toLowerCase(), { size: e.size, start: e.start, isMini });
    }
    if (e.type !== 2 && e.child < 0xFFFFFFF0) this._walkMetaOnly(e.child, e.type === 5 ? '' : path, depth + 1);
    if (e.lsib < 0xFFFFFFF0) this._walkMetaOnly(e.lsib, prefix, depth + 1);
    if (e.rsib < 0xFFFFFFF0) this._walkMetaOnly(e.rsib, prefix, depth + 1);
  }

  _so(sec) { return 512 + sec * this._ss; }

  _buildFAT(n) {
    const fat = []; let done = 0;
    const addSec = s => {
      if (s >= 0xFFFFFFF0) return;
      const off = this._so(s);
      for (let i = 0; i < this._ss / 4; i++) fat.push(this.dv.getUint32(off + i * 4, true));
      done++;
    };
    for (let i = 0; i < 109 && done < n; i++) { const s = this.dv.getUint32(0x4C + i * 4, true); if (s >= 0xFFFFFFF0) break; addSec(s); }
    let dif = this.dv.getUint32(0x44, true);
    while (dif < 0xFFFFFFF0 && done < n) {
      const off = this._so(dif);
      for (let i = 0; i < this._ss / 4 - 1 && done < n; i++) { const s = this.dv.getUint32(off + i * 4, true); if (s >= 0xFFFFFFF0) break; addSec(s); }
      dif = this.dv.getUint32(off + this._ss - 4, true);
    }
    return fat;
  }

  _buildMFAT(first, n) {
    const mf = []; let s = first;
    while (s < 0xFFFFFFF0 && n-- > 0) {
      const off = this._so(s);
      for (let i = 0; i < this._ss / 4; i++) mf.push(this.dv.getUint32(off + i * 4, true));
      s = this._fat[s] ?? 0xFFFFFFFE;
    }
    return mf;
  }

  _chain(start, size, mini) {
    if (size === 0 || start >= 0xFFFFFFF0) return new Uint8Array(0);
    const res = new Uint8Array(size < 0 ? 0 : size);
    const sz = mini ? this._ms : this._ss;
    const fat = mini ? this._mfat : this._fat;
    let sec = start, pos = 0;
    while (sec < 0xFFFFFFF0 && pos < size) {
      const take = Math.min(sz, size - pos);
      if (mini) { const off = sec * this._ms; res.set(this._mini.slice(off, off + take), pos); }
      else { const off = this._so(sec); res.set(this.buf.slice(off, off + take), pos); }
      pos += take; sec = fat[sec] ?? 0xFFFFFFFE;
    }
    return res;
  }

  _readDir(first) {
    const dir = []; let sec = first;
    while (sec < 0xFFFFFFF0) {
      const off = this._so(sec);
      for (let i = 0; i < this._ss / 128; i++) {
        const b = off + i * 128, nl = this.dv.getUint16(b + 64, true);
        if (!nl || nl > 64) {
          dir.push({ type: 0, name: '', start: 0, size: 0, child: 0xFFFFFFFF, lsib: 0xFFFFFFFF, rsib: 0xFFFFFFFF });
          continue;
        }
        let name = '';
        for (let j = 0; j < (nl - 2) / 2; j++) name += String.fromCharCode(this.dv.getUint16(b + j * 2, true));
        dir.push({
          name, type: this.buf[b + 66],
          lsib: this.dv.getUint32(b + 68, true),
          rsib: this.dv.getUint32(b + 72, true),
          child: this.dv.getUint32(b + 76, true),
          start: this.dv.getUint32(b + 116, true),
          size: this.dv.getUint32(b + 120, true),
        });
      }
      sec = this._fat[sec] ?? 0xFFFFFFFE;
    }
    return dir;
  }
}
