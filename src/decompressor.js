// ════════════════════════════════════════════════════════════════════════════
// Decompressor — async inflate/gunzip using DecompressionStream API, with a
// synchronous pako fallback for callers that can't `await` and for browsers
// where DecompressionStream is unavailable (e.g. old Safari).
//
// Surface area:
//   • tryDecompress(bytes, offset, format)   → async, preferred path
//   • tryAll(bytes, offset)                  → async, magic-byte sniff + try
//   • inflate(bytes, format)                 → async wrapper around tryDecompress
//   • inflateSync(bytes, format)             → NEW sync pako-only path for
//                                              renderers that run inside
//                                              analyzeForSecurity (which must
//                                              return synchronously).
// ════════════════════════════════════════════════════════════════════════════

const Decompressor = {

  /** Maximum inflated size allowed — prevents zip-bomb expansion. Uses shared PARSER_LIMITS. */
  MAX_OUTPUT: (typeof PARSER_LIMITS !== 'undefined' ? PARSER_LIMITS.MAX_UNCOMPRESSED : 50 * 1024 * 1024),

  /** Is the browser-native DecompressionStream API available? */
  _hasNativeDS: (typeof DecompressionStream !== 'undefined'),

  /** Is the vendored pako library available? */
  _hasPako: (typeof pako !== 'undefined' && pako && typeof pako.inflate === 'function'),

  /**
   * Attempt to decompress `bytes` starting at `offset` using the given format.
   * Tries the native DecompressionStream first (zero-copy, no extra JS in
   * the hot path) and falls back to pako's synchronous inflate when the API
   * is missing OR when the native call rejects with a generic error.
   *
   * @param {Uint8Array} bytes   Full input buffer.
   * @param {number}     offset  Byte offset to start from.
   * @param {string}     format  'deflate' | 'gzip' | 'deflate-raw'
   * @returns {Promise<{success:boolean, data:Uint8Array|null, format:string}>}
   */
  async tryDecompress(bytes, offset, format) {
    const slice = bytes.subarray(offset);
    if (slice.length < 4) return { success: false, data: null, format };

    // ── Native DecompressionStream path ─────────────────────────────────
    if (Decompressor._hasNativeDS) {
      try {
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
            // Swallow the post-cancel rejection — `cancel()` returns a
            // promise that may reject if the stream errored after we
            // started cancelling, and we don't care: we're already on the
            // failure path.
            try { await reader.cancel(); } catch (_) { /* best-effort */ }
            return { success: false, data: null, format }; // zip-bomb guard
          }
          chunks.push(value);
        }

        if (totalLen === 0) {
          // Fall through to pako — empty native output on a clearly-
          // non-empty input usually means a format mismatch rather than
          // genuine empty data.
          if (!Decompressor._hasPako) return { success: false, data: null, format };
        } else {
          const out = new Uint8Array(totalLen);
          let pos = 0;
          for (const c of chunks) { out.set(c, pos); pos += c.byteLength; }
          // NOTE: we used to treat all-zero output as failure here. That
          // heuristic silently corrupted legitimate sparse / zero-padded
          // payloads. The native `DecompressionStream` already throws on
          // genuine format mismatch — if we got here without the catch
          // firing, the bytes are real, even if they're all zero.
          return { success: true, data: out, format };
        }
      } catch (_) {
        // Native path refused — fall through to pako if available.
      }
    }

    // ── pako fallback ────────────────────────────────────────────────────
    // pako throws on genuine format mismatch — we rely on the explicit
    // try/catch to detect failure rather than the legacy all-zero
    // heuristic (which silently corrupted legitimate sparse / zero-padded
    // payloads).
    if (Decompressor._hasPako) {
      try {
        const out = Decompressor._pakoInflate(slice, format);
        if (!out || out.length === 0) {
          return { success: false, data: null, format };
        }
        if (out.length > Decompressor.MAX_OUTPUT) {
          return { success: false, data: null, format };
        }
        return { success: true, data: out, format };
      } catch (_) {
        return { success: false, data: null, format };
      }
    }

    return { success: false, data: null, format };
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
    const r = await this.tryDecompress(bytes, offset, 'deflate-raw');
    if (r.success && r.data.length > 8) return { data: r.data, format: 'raw deflate' };

    return null;
  },

  /**
   * Inflate a known-compressed byte array with a given format.
   * @param {Uint8Array} compressedBytes
   * @param {string}     format  'deflate' | 'gzip' | 'deflate-raw'
   * @returns {Promise<Uint8Array|null>}
   */
  async inflate(compressedBytes, format) {
    const r = await this.tryDecompress(compressedBytes, 0, format);
    return r.success ? r.data : null;
  },

  /**
   * SYNCHRONOUS inflate via pako. Used by renderers that run inside
   * analyzeForSecurity (sync contract) — most notably deep PE resource
   * decompression, embedded-blob decoders, and legacy CFB streams where
   * awaiting a promise would break the caller's return path.
   *
   * Returns null if pako is unavailable, the format is unknown, the input
   * is empty, inflation fails, or the output exceeds MAX_OUTPUT.
   *
   * @param {Uint8Array} compressedBytes
   * @param {string}     format  'deflate' | 'gzip' | 'deflate-raw' | 'zlib'
   * @returns {Uint8Array|null}
   */
  inflateSync(compressedBytes, format) {
    if (!Decompressor._hasPako) return null;
    if (!compressedBytes || !compressedBytes.length) return null;
    try {
      const out = Decompressor._pakoInflate(compressedBytes, format);
      // Rely on pako's own throw to distinguish failure from genuine
      // empty / all-zero output. The legacy `out.every(b => b === 0)`
      // gate silently corrupted legitimate sparse / zero-padded payloads
      // (sparse files, freshly zero-stamped sections of binaries, etc.).
      if (!out || out.length === 0) return null;
      if (out.length > Decompressor.MAX_OUTPUT) return null;
      return out;
    } catch (_) {
      return null;
    }
  },

  /**
   * Internal pako dispatcher — maps our format names to the pako call
   * that handles them. Any exception is allowed to propagate so callers
   * can decide whether to swallow or log.
   */
  _pakoInflate(bytes, format) {
    switch (format) {
      case 'gzip':
        return pako.ungzip(bytes);
      case 'deflate':
      case 'zlib':
        return pako.inflate(bytes);
      case 'deflate-raw':
        return pako.inflateRaw(bytes);
      default:
        return null;
    }
  },
};
