'use strict';
// ════════════════════════════════════════════════════════════════════════════
// qr-decoder.js — Shared QR-code decoding helper
//
// QR codes are a common "quishing" vector — the payload bypasses every
// text/URL scanner the document went through on the way in because the
// real target URL lives inside a raster image nobody ever OCR'd. This
// helper turns any image surface Loupe renders (standalone rasters, PDF
// page rasters, SVG-embedded rasters, OneNote embedded objects, EML image
// parts) into a decoded payload that:
//   • lands in `findings.metadata.qrPayload` / `qrVersion` / `qrPayloadType`
//   • mirrors as an IOC via pushIOC() — classified by payload prefix:
//       http(s)://    → IOC.URL       (severity: medium — quishing default)
//       mailto:       → IOC.EMAIL
//       WIFI: / GEO: / SMSTO: / TEL: / BEGIN:VCARD / MATMSG: → IOC.PATTERN
//       otherwise     → IOC.PATTERN (info) with short preview
//
// Depends on: window.jsQR (vendor/jsqr.min.js), pushIOC + IOC (constants.js)
//
// Used by: ImageRenderer, PdfRenderer, SvgRenderer, OneNoteRenderer,
//          EmlRenderer. Each caller funnels its own pixel data or raw
//          image bytes through one of the two sync/async entry points.
//
// Safety:
//   • Swallows every error — a broken vendor load never crashes analysis.
//   • Image surfaces over ~4 MP (width * height) are downscaled to fit in
//     2048×2048 before scanning so a hostile multi-gigapixel PNG can't
//     pin the main thread.
//   • jsQR only detects ONE QR per image surface — documented limitation.
// ════════════════════════════════════════════════════════════════════════════
class QrDecoder {

  // ── Sentinels ───────────────────────────────────────────────────────
  static MAX_PIXELS = 4 * 1024 * 1024; // 4 MP — above this we downscale
  static MAX_SIDE = 2048;               // Downscale target cap
  static PAYLOAD_PREVIEW = 140;         // Truncation cap for metadata + IOC preview

  /**
   * Synchronous decode of an already-materialised RGBA buffer. Returns
   * a result object or `null` on no-match / unavailable jsQR.
   *
   * @param {Uint8ClampedArray|Uint8Array} rgba  width*height*4 bytes, RGBA
   * @param {number} width
   * @param {number} height
   * @returns {{payload:string, version:number, payloadType:string}|null}
   */
  static decodeRGBA(rgba, width, height) {
    if (typeof jsQR === 'undefined' || !jsQR) return null;
    if (!rgba || !width || !height) return null;
    if (rgba.length < width * height * 4) return null;
    try {
      // Downscale guard — jsQR's cost is O(width*height), so cap input.
      if (width * height > QrDecoder.MAX_PIXELS) {
        const scaled = QrDecoder._downscaleRGBA(rgba, width, height);
        if (!scaled) return null;
        rgba = scaled.rgba; width = scaled.width; height = scaled.height;
      }
      // jsQR wants a Uint8ClampedArray; coerce if caller passed Uint8Array.
      const clamped = (rgba instanceof Uint8ClampedArray)
        ? rgba
        : new Uint8ClampedArray(rgba.buffer, rgba.byteOffset, rgba.byteLength);
      const r = jsQR(clamped, width, height, { inversionAttempts: 'attemptBoth' });
      if (!r || typeof r.data !== 'string' || !r.data.length) return null;
      return {
        payload: r.data,
        version: (r.version && typeof r.version === 'number') ? r.version : 0,
        payloadType: QrDecoder._classify(r.data),
      };
    } catch (_) { return null; }
  }

  /**
   * Asynchronous decode of a raw image blob (PNG / JPEG / GIF / WEBP /
   * BMP / ICO / AVIF). We create a transient object URL, draw the image
   * onto an offscreen canvas, pull RGBA, and hand to `decodeRGBA`.
   * TIFF is NOT supported here — callers with TIFF already have the
   * decoded RGBA via UTIF and should call `decodeRGBA` directly.
   *
   * @param {ArrayBuffer|Uint8Array} buffer
   * @param {string} mime  e.g. 'image/png'
   * @returns {Promise<{payload:string, version:number, payloadType:string}|null>}
   */
  static decodeBlob(buffer, mime) {
    if (typeof jsQR === 'undefined' || !jsQR) return Promise.resolve(null);
    if (!buffer || !buffer.byteLength) return Promise.resolve(null);
    return new Promise(resolve => {
      let url = null;
      try {
        const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;
        const blob = new Blob([bytes], { type: mime || 'application/octet-stream' });
        url = URL.createObjectURL(blob);
        const img = new Image();
        const cleanup = () => { try { URL.revokeObjectURL(url); } catch (_) {} };
        img.onload = () => {
          try {
            let w = img.naturalWidth || img.width;
            let h = img.naturalHeight || img.height;
            if (!w || !h) { cleanup(); resolve(null); return; }
            // Downscale at draw-time if the source is huge.
            if (w * h > QrDecoder.MAX_PIXELS) {
              const scale = Math.sqrt(QrDecoder.MAX_PIXELS / (w * h));
              w = Math.max(1, Math.floor(w * scale));
              h = Math.max(1, Math.floor(h * scale));
            }
            const canvas = document.createElement('canvas');
            canvas.width = w; canvas.height = h;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(img, 0, 0, w, h);
            const data = ctx.getImageData(0, 0, w, h);
            cleanup();
            resolve(QrDecoder.decodeRGBA(data.data, w, h));
          } catch (_) { cleanup(); resolve(null); }
        };
        img.onerror = () => { cleanup(); resolve(null); };
        img.src = url;
      } catch (_) { if (url) { try { URL.revokeObjectURL(url); } catch (__){} } resolve(null); }
    });
  }

  /**
   * Apply a decoded QR payload to a findings object. Writes metadata
   * keys and mirrors as an IOC classified by payload type. Safe to
   * call multiple times for the same `f` (each call is a separate
   * IOC entry, useful for multi-page PDFs / multi-embed containers).
   *
   * @param {object} findings   analyzeForSecurity() findings object
   * @param {object} result     { payload, version, payloadType }
   * @param {string} [source]   short label — 'image' | 'pdf-page-3' | etc.
   */
  static applyToFindings(findings, result, source) {
    if (!findings || !result || typeof result.payload !== 'string') return;
    const payload = result.payload;
    const preview = payload.length > QrDecoder.PAYLOAD_PREVIEW
      ? payload.slice(0, QrDecoder.PAYLOAD_PREVIEW) + '…'
      : payload;
    const src = source ? String(source) : 'image';

    // ── Metadata panel ─────────────────────────────────────────────
    // If a findings already carries a qrPayload (e.g. PDF page 1 hit
    // first), append so the metadata panel keeps the earlier context
    // visible; otherwise seed a fresh scalar.
    const prior = findings.metadata && findings.metadata.qrPayload;
    findings.metadata = findings.metadata || {};
    if (prior && prior !== preview) {
      // Promote to a list-shaped metadata value once a second QR lands.
      const list = Array.isArray(findings.metadata.qrPayload)
        ? findings.metadata.qrPayload.slice()
        : [String(prior)];
      list.push(`${src}: ${preview}`);
      findings.metadata.qrPayload = list;
    } else {
      findings.metadata.qrPayload = `${src}: ${preview}`;
    }
    if (result.version) findings.metadata.qrVersion = result.version;
    findings.metadata.qrPayloadType = result.payloadType || 'text';
    findings.metadata.qrSource = src;

    // ── IOC mirror ─────────────────────────────────────────────────
    // Classify by payload prefix. Quishing = URL payload; severity
    // bumped to 'medium' there because the whole reason to surface QR
    // content is to catch the URL the document tried to hide.
    const classified = QrDecoder._iocShape(payload, src);
    if (classified) pushIOC(findings, classified);

    // Escalate overall risk when a URL is present. We never de-escalate;
    // analyzers upstream may have already set 'high' for other reasons.
    if (classified && classified.type === IOC.URL) {
      if (findings.risk === 'low' || !findings.risk) findings.risk = 'medium';
    }
  }

  // ── Internal helpers ────────────────────────────────────────────────

  /** Classify a decoded payload by its leading scheme / structured-URI prefix. */
  static _classify(payload) {
    const s = String(payload || '').trim();
    if (/^https?:\/\//i.test(s)) return 'url';
    if (/^mailto:/i.test(s))     return 'email';
    if (/^wifi:/i.test(s))       return 'wifi';
    if (/^geo:/i.test(s))        return 'geo';
    if (/^tel:/i.test(s))        return 'tel';
    if (/^smsto:/i.test(s))      return 'sms';
    if (/^matmsg:/i.test(s))     return 'email';
    if (/^begin:vcard/i.test(s)) return 'vcard';
    if (/^otpauth:\/\//i.test(s)) return 'otp';
    if (/^bitcoin:/i.test(s))    return 'crypto';
    return 'text';
  }

  /**
   * Build the pushIOC() opts for a decoded payload. The severity/type
   * table is deliberately narrow: URLs are the quishing headline risk;
   * everything else is an info-level pivot.
   */
  static _iocShape(payload, source) {
    const s = String(payload || '').trim();
    if (!s) return null;
    const preview = s.length > QrDecoder.PAYLOAD_PREVIEW
      ? s.slice(0, QrDecoder.PAYLOAD_PREVIEW) + '…'
      : s;
    const note = `QR code payload (${source})`;

    if (/^https?:\/\//i.test(s)) {
      // Pass the raw URL as the IOC value so the sidebar's URL pivot
      // row copies / filters cleanly, and let pushIOC() auto-emit the
      // IOC.DOMAIN sibling via tldts.
      return { type: IOC.URL, value: s, severity: 'medium', highlightText: s, note };
    }
    if (/^mailto:/i.test(s)) {
      const addr = s.replace(/^mailto:/i, '').split(/[?&]/)[0];
      return { type: IOC.EMAIL, value: addr || s, severity: 'info', highlightText: addr || s, note };
    }
    if (/^tel:/i.test(s) || /^smsto:/i.test(s)) {
      return { type: IOC.PATTERN, value: `QR ${s.split(':')[0].toUpperCase()}: ${preview}`, severity: 'info', highlightText: preview, note };
    }
    if (/^wifi:/i.test(s)) {
      // WIFI:S:<ssid>;T:<WPA|WEP|nopass>;P:<pw>;H:<true|false>;;
      // Surface just the SSID in the preview — exposing the password
      // in the sidebar is the wrong default.
      const m = s.match(/S:([^;]*)/i);
      const ssid = m ? m[1] : '(unknown)';
      return { type: IOC.PATTERN, value: `QR WIFI SSID: ${ssid}`, severity: 'info', highlightText: ssid, note };
    }
    if (/^geo:/i.test(s)) {
      const coords = s.replace(/^geo:/i, '').split('?')[0];
      return { type: IOC.PATTERN, value: `QR GEO: ${coords}`, severity: 'info', highlightText: coords, note };
    }
    if (/^begin:vcard/i.test(s)) {
      return { type: IOC.PATTERN, value: `QR vCard (${s.length} bytes)`, severity: 'info', note };
    }
    if (/^otpauth:\/\//i.test(s)) {
      // OTP seeds are credentials — surface the label only, not the secret.
      const label = (s.match(/^otpauth:\/\/[^/]+\/([^?]+)/i) || [])[1] || '(unknown)';
      return { type: IOC.PATTERN, value: `QR OTP: ${decodeURIComponent(label)}`, severity: 'medium', highlightText: label, note: `${note} — TOTP/HOTP seed` };
    }
    if (/^bitcoin:/i.test(s)) {
      return { type: IOC.PATTERN, value: `QR BITCOIN: ${preview}`, severity: 'medium', highlightText: preview, note };
    }
    return { type: IOC.PATTERN, value: `QR text: ${preview}`, severity: 'info', highlightText: preview, note };
  }

  /**
   * Downscale an RGBA buffer via nearest-neighbour sampling. Pure-JS
   * (no canvas) so the caller-provided buffer is scaled without
   * allocating a DOM element — useful for the sync TIFF path.
   */
  static _downscaleRGBA(rgba, width, height) {
    try {
      const scale = Math.sqrt(QrDecoder.MAX_PIXELS / (width * height));
      const nw = Math.max(1, Math.floor(width * scale));
      const nh = Math.max(1, Math.floor(height * scale));
      const out = new Uint8ClampedArray(nw * nh * 4);
      const xRatio = width / nw;
      const yRatio = height / nh;
      for (let y = 0; y < nh; y++) {
        const sy = Math.floor(y * yRatio);
        for (let x = 0; x < nw; x++) {
          const sx = Math.floor(x * xRatio);
          const si = (sy * width + sx) * 4;
          const di = (y * nw + x) * 4;
          out[di]     = rgba[si];
          out[di + 1] = rgba[si + 1];
          out[di + 2] = rgba[si + 2];
          out[di + 3] = rgba[si + 3];
        }
      }
      return { rgba: out, width: nw, height: nh };
    } catch (_) { return null; }
  }
}
