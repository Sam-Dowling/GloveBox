'use strict';
// ════════════════════════════════════════════════════════════════════════════
// image-renderer.js — Renders image files (PNG, JPEG, GIF, BMP, WEBP, ICO)
// Shows the image with metadata and checks for steganography indicators.
// Depends on: constants.js (IOC)
// ════════════════════════════════════════════════════════════════════════════
class ImageRenderer {

  static MIME_MAP = {
    jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png', gif: 'image/gif',
    bmp: 'image/bmp', webp: 'image/webp', ico: 'image/x-icon', tif: 'image/tiff',
    tiff: 'image/tiff', avif: 'image/avif',
  };

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const ext = (fileName || '').split('.').pop().toLowerCase();
    const mime = ImageRenderer.MIME_MAP[ext] || 'image/png';
    const wrap = document.createElement('div'); wrap.className = 'image-view';

    // Banner
    const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
    const bannerStrong = document.createElement('strong'); bannerStrong.textContent = 'Image Preview';
    banner.appendChild(bannerStrong);
    banner.appendChild(document.createTextNode(` — ${ext.toUpperCase()} image (${this._fmtBytes(bytes.length)})`));
    wrap.appendChild(banner);

    // Image element
    const imgWrap = document.createElement('div'); imgWrap.className = 'image-preview-wrap';
    const img = document.createElement('img');
    img.className = 'image-preview';
    const blob = new Blob([bytes], { type: mime });
    const blobUrl = URL.createObjectURL(blob);
    img.src = blobUrl;
    img.alt = fileName || 'Image preview';
    img.title = 'Right-click to save or inspect';

    // Show dimensions once loaded
    const infoDiv = document.createElement('div'); infoDiv.className = 'image-info';
    infoDiv.textContent = `Loading image…`;
    img.addEventListener('load', () => {
      infoDiv.textContent = `${img.naturalWidth} × ${img.naturalHeight} px  ·  ${ext.toUpperCase()}  ·  ${this._fmtBytes(bytes.length)}`;
      // Revoke blob URL after image is loaded to free memory
      URL.revokeObjectURL(blobUrl);
    });
    img.addEventListener('error', () => {
      infoDiv.textContent = `Failed to render image — file may be corrupted or unsupported format`;
      infoDiv.style.color = 'var(--risk-high)';
      // Revoke blob URL on error to free memory
      URL.revokeObjectURL(blobUrl);
    });

    imgWrap.appendChild(img);
    wrap.appendChild(imgWrap);
    wrap.appendChild(infoDiv);

    // Hex header (first 32 bytes)
    const headerDiv = document.createElement('div'); headerDiv.className = 'image-hex-header';
    const hexStr = Array.from(bytes.subarray(0, Math.min(32, bytes.length)))
      .map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
    headerDiv.textContent = `Header: ${hexStr}`;
    wrap.appendChild(headerDiv);

    return wrap;
  }

  analyzeForSecurity(buffer, fileName) {
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: []
    };

    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const ext = (fileName || '').split('.').pop().toLowerCase();

    // Check for appended data after image EOF (steganography indicator)
    if (ext === 'png' || ext === 'PNG') {
      // PNG ends with IEND chunk: 49 45 4E 44 AE 42 60 82
      const iend = [0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82];
      for (let i = bytes.length - 8; i >= 8; i--) {
        let match = true;
        for (let j = 0; j < 8; j++) { if (bytes[i + j] !== iend[j]) { match = false; break; } }
        if (match) {
          const endPos = i + 8;
          if (endPos < bytes.length) {
            const extra = bytes.length - endPos;
            f.externalRefs.push({
              type: IOC.PATTERN,
              url: `${this._fmtBytes(extra)} of data appended after PNG IEND chunk — possible steganography or embedded payload`,
              severity: 'medium'
            });
            f.risk = 'medium';
          }
          break;
        }
      }
    }

    if (['jpg', 'jpeg'].includes(ext)) {
      // JPEG ends with FFD9
      let lastFFD9 = -1;
      for (let i = bytes.length - 2; i >= 2; i--) {
        if (bytes[i] === 0xFF && bytes[i + 1] === 0xD9) { lastFFD9 = i; break; }
      }
      if (lastFFD9 >= 0 && lastFFD9 + 2 < bytes.length) {
        const extra = bytes.length - lastFFD9 - 2;
        if (extra > 0) {
          f.externalRefs.push({
            type: IOC.PATTERN,
            url: `${this._fmtBytes(extra)} of data appended after JPEG EOI marker — possible steganography or embedded payload`,
            severity: 'medium'
          });
          f.risk = 'medium';
        }
      }
    }

    // Check for embedded PE header inside image
    for (let i = 16; i < bytes.length - 4; i++) {
      if (bytes[i] === 0x4D && bytes[i + 1] === 0x5A && bytes[i + 2] === 0x90 && bytes[i + 3] === 0x00) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: `Embedded PE (MZ) header found at offset ${i} inside image — hidden executable`,
          severity: 'high'
        });
        f.risk = 'high';
        break;
      }
    }

    // Check for embedded ZIP inside image (polyglot)
    for (let i = 16; i < bytes.length - 4; i++) {
      if (bytes[i] === 0x50 && bytes[i + 1] === 0x4B && bytes[i + 2] === 0x03 && bytes[i + 3] === 0x04) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: `Embedded ZIP archive found at offset ${i} inside image — polyglot file`,
          severity: 'medium'
        });
        if (f.risk === 'low') f.risk = 'medium';
        break;
      }
    }

    // Extract EXIF-like metadata from JPEG (simplified)
    if (['jpg', 'jpeg'].includes(ext) && bytes[0] === 0xFF && bytes[1] === 0xD8) {
      // Look for EXIF marker (FFE1)
      for (let i = 2; i < Math.min(bytes.length - 10, 65535); i++) {
        if (bytes[i] === 0xFF && bytes[i + 1] === 0xE1) {
          // Found EXIF — extract readable strings
          const exifEnd = Math.min(i + 500, bytes.length);
          let str = '';
          for (let j = i + 4; j < exifEnd; j++) {
            const b = bytes[j];
            if (b >= 0x20 && b < 0x7F) str += String.fromCharCode(b);
            else if (str.length >= 6) { break; }
            else str = '';
          }
          if (str.length >= 6) {
            f.metadata.exif = str.slice(0, 100);
          }
          break;
        }
      }
    }

    f.metadata.format = ext.toUpperCase();
    f.metadata.size = bytes.length;

    // Pattern detection is handled entirely by YARA (auto-scan on file load)
    return f;
  }

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
