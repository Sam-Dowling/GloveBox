// ════════════════════════════════════════════════════════════════════════════
// Decompressor — async inflate/gunzip using DecompressionStream API
// ════════════════════════════════════════════════════════════════════════════

const Decompressor = {

  /** Maximum inflated size allowed (50 MB) — prevents zip-bomb expansion. */
  MAX_OUTPUT: 50 * 1024 * 1024,

  /**
   * Attempt to decompress `bytes` starting at `offset` using the given format.
   * @param {Uint8Array} bytes   Full input buffer.
   * @param {number}     offset  Byte offset to start from.
   * @param {string}     format  'deflate' | 'gzip' | 'deflate-raw'
   * @returns {Promise<{success:boolean, data:Uint8Array|null, format:string}>}
   */
  async tryDecompress(bytes, offset, format) {
    try {
      const slice = bytes.subarray(offset);
      if (slice.length < 4) return { success: false, data: null, format };

      const blob = new Blob([slice]);
      const ds = new DecompressionStream(format);
      const stream = blob.stream().pipeThrough(ds);
      const reader = stream.getReader();

      const chunks = [];
      let totalLen = 0;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        totalLen += value.byteLength;
        if (totalLen > Decompressor.MAX_OUTPUT) {
          reader.cancel();
          return { success: false, data: null, format }; // zip-bomb guard
        }
        chunks.push(value);
      }

      if (totalLen === 0) return { success: false, data: null, format };

      // Merge chunks
      const out = new Uint8Array(totalLen);
      let pos = 0;
      for (const c of chunks) { out.set(c, pos); pos += c.byteLength; }

      // Reject all-null output
      if (out.every(b => b === 0)) return { success: false, data: null, format };

      return { success: true, data: out, format };
    } catch (_) {
      return { success: false, data: null, format };
    }
  },

  /**
   * Try all supported decompression formats at a given offset.
   * Returns the first successful result, or null.
   * @param {Uint8Array} bytes
   * @param {number}     offset
   * @returns {Promise<{data:Uint8Array, format:string}|null>}
   */
  async tryAll(bytes, offset) {
    // Detect format from magic bytes
    const b0 = bytes[offset], b1 = bytes[offset + 1] || 0;

    // Gzip: 1F 8B
    if (b0 === 0x1F && b1 === 0x8B) {
      const r = await this.tryDecompress(bytes, offset, 'gzip');
      if (r.success) return { data: r.data, format: 'gzip' };
    }

    // Zlib: 78 01/5E/9C/DA
    if (b0 === 0x78 && (b1 === 0x01 || b1 === 0x5E || b1 === 0x9C || b1 === 0xDA)) {
      const r = await this.tryDecompress(bytes, offset, 'deflate');
      if (r.success) return { data: r.data, format: 'zlib' };
    }

    // Raw deflate — try as last resort
    const r = await this.tryDecompress(bytes, offset, 'raw');
    if (r.success && r.data.length > 8) return { data: r.data, format: 'raw deflate' };

    return null;
  },

  /**
   * Inflate a known-compressed byte array with a given format.
   * @param {Uint8Array} compressedBytes
   * @param {string}     format  'deflate' | 'gzip' | 'raw'
   * @returns {Promise<Uint8Array|null>}
   */
  async inflate(compressedBytes, format) {
    const r = await this.tryDecompress(compressedBytes, 0, format);
    return r.success ? r.data : null;
  },
};
