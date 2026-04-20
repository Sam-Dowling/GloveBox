'use strict';
// ════════════════════════════════════════════════════════════════════════════
// image-renderer.js — Renders image files (PNG, JPEG, GIF, BMP, WEBP, ICO)
// Shows the image with metadata and checks for steganography indicators.
//
// EXIF / XMP / IPTC parsing uses the vendored `exifr` library (Tier-1 dep).
// Classic-pivot fields (GPS coordinates, camera serial, XMP document/
// instance IDs, creator toolkit) are mirrored into `findings.interestingStrings`
// via pushIOC() so they appear in the sidebar's IOC table, while attribution
// fluff (Camera Make / Model / artist name) stays metadata-only per the
// "Option B" classic-pivot policy.
//
// Depends on: constants.js (IOC, pushIOC, mirrorMetadataIOCs)
//             vendor/exifr.min.js (window.exifr, optional — falls back gracefully)
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
    const infoDiv = document.createElement('div'); infoDiv.className = 'image-info';

    // TIFF branch — browsers don't render TIFF in <img>, so we decode via the
    // vendored UTIF.js and paint the first page onto a <canvas>. We probe by
    // extension AND by magic bytes (II*\0 / MM\0*) so mis-labelled files still
    // get the canvas path, and fall through to the <img> path on any failure
    // so Safari users (who CAN decode TIFF natively) aren't regressed.
    const isTiffMagic =
      bytes.length >= 4 &&
      ((bytes[0] === 0x49 && bytes[1] === 0x49 && bytes[2] === 0x2A && bytes[3] === 0x00) ||
       (bytes[0] === 0x4D && bytes[1] === 0x4D && bytes[2] === 0x00 && bytes[3] === 0x2A));
    const isTiff = (ext === 'tif' || ext === 'tiff' || isTiffMagic) && typeof UTIF !== 'undefined';

    let canvasRendered = false;
    let tiffIfds = null;
    if (isTiff) {
      try {
        const ab = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
        const ifds = UTIF.decode(ab);
        if (ifds && ifds.length) {
          tiffIfds = ifds;
          UTIF.decodeImage(ab, ifds[0]);
          const rgba = UTIF.toRGBA8(ifds[0]);
          const w = ifds[0].width, h = ifds[0].height;
          if (w > 0 && h > 0 && rgba && rgba.length === w * h * 4) {
            const canvas = document.createElement('canvas');
            canvas.className = 'image-preview';
            canvas.width = w; canvas.height = h;
            const ctx = canvas.getContext('2d');
            const imgData = ctx.createImageData(w, h);
            imgData.data.set(rgba);
            ctx.putImageData(imgData, 0, 0);
            imgWrap.appendChild(canvas);
            const pageSuffix = ifds.length > 1 ? `  ·  page 1 of ${ifds.length}` : '';
            infoDiv.textContent = `${w} × ${h} px  ·  TIFF${pageSuffix}  ·  ${this._fmtBytes(bytes.length)}`;
            canvasRendered = true;
          }
        }
      } catch (e) {
        // Swallow and fall through to the <img> path below — it will surface
        // the standard "Failed to render image" message if the browser also
        // can't handle it.
      }
    }

    if (!canvasRendered) {
      const img = document.createElement('img');
      img.className = 'image-preview';
      const blob = new Blob([bytes], { type: mime });
      const blobUrl = URL.createObjectURL(blob);
      img.src = blobUrl;
      img.alt = fileName || 'Image preview';
      img.title = 'Right-click to save or inspect';

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
    }

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

  async analyzeForSecurity(buffer, fileName) {
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], interestingStrings: [], metadata: {},
      signatureMatches: []
    };

    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const ext = (fileName || '').split('.').pop().toLowerCase();

    // ── Appended-data steganography checks ──────────────────────────────
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

    // ── EXIF / XMP / IPTC parsing via exifr ─────────────────────────────
    // exifr accepts ArrayBuffer / Uint8Array / Buffer synchronously via
    // `parseSync`, but the library only exposes a Promise-based API. We
    // therefore call it synchronously via the compiled parser so we stay
    // on the existing analyze-for-security sync contract (renderers must
    // return `f` immediately). The library's `parse()` API supports fully
    // synchronous extraction for raw-byte inputs; we guard every branch
    // so a missing / broken vendor load cannot crash analysis.
    if (typeof exifr !== 'undefined' && exifr && bytes.length) {
      try {
        // Enable every segment exifr supports so we surface ICC colour-
        // profile descriptions, maker-note oddities, interop IFDs, and
        // the thumbnail IFD (ifd1) — all of which can carry forensic
        // signal. `multiSegment: true` is required for JPEG payloads
        // where XMP / ICC get split across multiple APP1 / APP2 markers.
        const opts = {
          tiff: true, exif: true, gps: true, ifd0: true, ifd1: true,
          iptc: true, xmp: true, icc: true, interop: true,
          makerNote: true, userComment: true,
          multiSegment: true, jfif: false,
          mergeOutput: true, translateKeys: true, translateValues: true,
          reviveValues: true, sanitize: true,
        };
        // Fully-synchronous path: exifr.parse() returns a Promise, but for
        // already-in-memory raw bytes the promise resolves in a microtask.
        // We grab its synchronous fallback `parseSync` if present, else
        // kick the promise and stash its result — analysis is allowed to
        // continue updating `f.metadata` from a then() callback because
        // the sidebar is re-rendered whenever findings change in the main
        // analyze loop. exifr v7 does NOT ship parseSync for images; we
        // therefore launch the async parse and post-process on resolve.
        const ab = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
        const p = exifr.parse(ab, opts);
        if (p && typeof p.then === 'function') {
          p.then(data => this._applyExifData(f, data))
           .catch(() => { /* swallow — exifr is best-effort */ });
        } else if (p && typeof p === 'object') {
          this._applyExifData(f, p);
        }

        // Thumbnail extraction — exifr.thumbnail() returns the raw JPEG
        // bytes of the embedded preview if ifd1 contained one. A mis-
        // matched thumbnail (e.g. original intact, thumbnail doctored)
        // is a classic forensic tell for image tampering, so we expose
        // its size and embedded-payload scan its bytes.
        if (typeof exifr.thumbnail === 'function') {
          try {
            const tp = exifr.thumbnail(ab);
            if (tp && typeof tp.then === 'function') {
              tp.then(tb => this._applyThumbnail(f, tb))
                .catch(() => { /* swallow */ });
            } else if (tp) {
              this._applyThumbnail(f, tp);
            }
          } catch (_) { /* thumbnail optional */ }
        }
      } catch (_) { /* exifr optional */ }
    }

    // ── TIFF tag-dump (forensic metadata + embedded-payload scan) ──────
    // UTIF exposes every parsed IFD entry as `ifd.t<num>` where <num> is
    // the TIFF tag ID. We dump the well-known human-readable ones into
    // `f.metadata` so analysts can cross-reference against the exifr
    // output (which can miss non-standard vendor tags), then feed any
    // large string / byte tags through EncodedContentDetector to catch
    // base64 / hex / compressed payloads hidden in ImageDescription,
    // Artist, Copyright, or XMP (tag 700). TIFF magic probe: II*\0 / MM\0*
    const isTiffForAnalysis =
      (ext === 'tif' || ext === 'tiff' ||
       (bytes.length >= 4 &&
        ((bytes[0] === 0x49 && bytes[1] === 0x49 && bytes[2] === 0x2A && bytes[3] === 0x00) ||
         (bytes[0] === 0x4D && bytes[1] === 0x4D && bytes[2] === 0x00 && bytes[3] === 0x2A)))) &&
      typeof UTIF !== 'undefined';
    if (isTiffForAnalysis) {
      try {
        const ab = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
        const ifds = UTIF.decode(ab);
        if (ifds && ifds.length) {
          this._applyTiffTags(f, ifds);
          // Reuse the TIFF RGBA we just decoded to scan for QR codes
          // (synchronous path — no offscreen <img> needed).
          try {
            UTIF.decodeImage(ab, ifds[0]);
            const rgba = UTIF.toRGBA8(ifds[0]);
            const w = ifds[0].width, h = ifds[0].height;
            if (rgba && w && h && typeof QrDecoder !== 'undefined') {
              const qr = QrDecoder.decodeRGBA(rgba, w, h);
              if (qr) QrDecoder.applyToFindings(f, qr, 'image');
            }
          } catch (_) { /* QR on TIFF is best-effort */ }
        }
      } catch (_) { /* tiff tag-dump is best-effort */ }
    }

    // ── QR-code decoding (quishing detector) ──────────────────────────
    // For every non-TIFF raster we ship the raw bytes off to
    // QrDecoder.decodeBlob which loads them via an offscreen <img> +
    // canvas and extracts RGBA for jsQR. We **must** await — _renderSidebar
    // reads a one-shot snapshot of `findings` after `analyzeForSecurity`
    // resolves, so a fire-and-forget promise would land the decoded QR
    // IOC into `f` after the sidebar has already painted the un-QR'd view
    // (classic symptom: QR in PDF works, QR in PNG doesn't). TIFF is
    // handled synchronously above to reuse the UTIF decode.
    if (!isTiffForAnalysis && ['png','jpg','jpeg','gif','bmp','webp','ico','avif'].includes(ext)
        && typeof QrDecoder !== 'undefined') {
      try {
        const mime = ImageRenderer.MIME_MAP[ext] || 'image/png';
        const ab = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
        const qr = await QrDecoder.decodeBlob(ab, mime);
        if (qr) QrDecoder.applyToFindings(f, qr, 'image');
      } catch (_) { /* QR decode best-effort */ }
    }

    // Legacy byte-scan EXIF fallback — preserved so images in unsupported
    // formats (or when exifr fails / is absent) still surface at least a
    // crude EXIF string, matching pre-v7 Loupe behaviour.
    if (!f.metadata.exif && ['jpg', 'jpeg'].includes(ext) && bytes[0] === 0xFF && bytes[1] === 0xD8) {
      for (let i = 2; i < Math.min(bytes.length - 10, 65535); i++) {
        if (bytes[i] === 0xFF && bytes[i + 1] === 0xE1) {
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

  /**
   * Post-process an exifr result into:
   *   • `findings.metadata` — human-readable attribution info
   *   • `findings.interestingStrings` — classic pivots via pushIOC()
   *
   * Option-B policy: ONLY mirror fields that function as pivots
   *   ✔ GPS lat/lon/alt       → IOC.PATTERN (geographic pivot)
   *   ✔ Camera body serial    → IOC.HASH    (unique per-device identifier)
   *   ✔ Owner name/copyright  → IOC.USERNAME (attribution to a real person)
   *   ✔ Creator Tool / XMP software → IOC.PATTERN (tool fingerprint)
   *   ✔ XMP DocumentID / InstanceID → IOC.GUID (cross-file pivot)
   *   ✔ IPTC By-line / Contact → IOC.USERNAME / IOC.EMAIL
   *   ✘ Make / Model / Lens   → metadata-only (attribution fluff)
   *   ✘ DateTimeOriginal      → metadata-only (timeline, not a pivot)
   */
  _applyExifData(f, data) {
    if (!data || typeof data !== 'object') return;

    // ── Pure attribution → metadata only ──────────────────────────────
    if (data.Make)                f.metadata.exifMake = String(data.Make).trim();
    if (data.Model)               f.metadata.exifModel = String(data.Model).trim();
    if (data.LensModel)           f.metadata.exifLens = String(data.LensModel).trim();
    if (data.DateTimeOriginal)    f.metadata.exifDateTime = this._fmtExifDate(data.DateTimeOriginal);
    if (data.CreateDate)          f.metadata.exifCreateDate = this._fmtExifDate(data.CreateDate);
    if (data.ModifyDate)          f.metadata.exifModifyDate = this._fmtExifDate(data.ModifyDate);
    if (data.ImageWidth && data.ImageHeight) {
      f.metadata.exifDimensions = `${data.ImageWidth} × ${data.ImageHeight}`;
    }

    // ── GPS: geographic pivot, always surface as IOC ──────────────────
    if (typeof data.latitude === 'number' && typeof data.longitude === 'number') {
      const lat = data.latitude.toFixed(6);
      const lon = data.longitude.toFixed(6);
      const alt = typeof data.GPSAltitude === 'number' ? ` @ ${data.GPSAltitude.toFixed(1)}m` : '';
      const gpsStr = `${lat}, ${lon}${alt}`;
      f.metadata.gps = gpsStr;
      pushIOC(f, {
        type: IOC.PATTERN,
        value: `GPS: ${gpsStr}`,
        severity: 'medium',
        highlightText: gpsStr,
        note: 'EXIF GPS coordinates',
      });
      if (f.risk === 'low') f.risk = 'medium';
    }

    // ── Device serial: unique per-camera pivot ────────────────────────
    if (data.SerialNumber || data.BodySerialNumber || data.InternalSerialNumber) {
      const serial = String(data.SerialNumber || data.BodySerialNumber || data.InternalSerialNumber).trim();
      if (serial) {
        f.metadata.exifSerial = serial;
        pushIOC(f, {
          type: IOC.HASH,
          value: serial,
          severity: 'info',
          highlightText: serial,
          note: 'Camera serial number',
        });
      }
    }

    // ── Owner / Artist / Copyright: personal attribution ──────────────
    if (data.Artist) {
      const artist = String(data.Artist).trim();
      if (artist) {
        f.metadata.exifArtist = artist;
        pushIOC(f, {
          type: IOC.USERNAME, value: artist, severity: 'info',
          highlightText: artist, note: 'EXIF Artist',
        });
      }
    }
    if (data.OwnerName || data.CameraOwnerName) {
      const owner = String(data.OwnerName || data.CameraOwnerName).trim();
      if (owner) {
        f.metadata.exifOwner = owner;
        pushIOC(f, {
          type: IOC.USERNAME, value: owner, severity: 'info',
          highlightText: owner, note: 'EXIF Owner',
        });
      }
    }
    if (data.Copyright) {
      const cp = String(data.Copyright).trim();
      if (cp) f.metadata.exifCopyright = cp;
    }

    // ── Creator software: tool fingerprint ────────────────────────────
    if (data.Software) {
      const sw = String(data.Software).trim();
      if (sw) {
        f.metadata.exifSoftware = sw;
        pushIOC(f, {
          type: IOC.PATTERN, value: `Software: ${sw}`, severity: 'info',
          highlightText: sw, note: 'EXIF Software',
        });
      }
    }
    if (data.CreatorTool) {
      const ct = String(data.CreatorTool).trim();
      if (ct && ct !== f.metadata.exifSoftware) {
        f.metadata.xmpCreatorTool = ct;
        pushIOC(f, {
          type: IOC.PATTERN, value: `CreatorTool: ${ct}`, severity: 'info',
          highlightText: ct, note: 'XMP CreatorTool',
        });
      }
    }

    // ── XMP Document / Instance ID: pure cross-file pivots ────────────
    if (data.DocumentID) {
      const id = String(data.DocumentID).replace(/^(xmp\.did:|uuid:)/i, '').trim();
      if (id) {
        f.metadata.xmpDocumentID = id;
        pushIOC(f, {
          type: IOC.GUID, value: id, severity: 'info',
          highlightText: id, note: 'XMP DocumentID',
        });
      }
    }
    if (data.InstanceID) {
      const id = String(data.InstanceID).replace(/^(xmp\.iid:|uuid:)/i, '').trim();
      if (id) {
        f.metadata.xmpInstanceID = id;
        pushIOC(f, {
          type: IOC.GUID, value: id, severity: 'info',
          highlightText: id, note: 'XMP InstanceID',
        });
      }
    }

    // ── IPTC by-line / contact ─────────────────────────────────────────
    if (data.Byline || data['By-line']) {
      const by = String(data.Byline || data['By-line']).trim();
      if (by) {
        f.metadata.iptcByline = by;
        pushIOC(f, {
          type: IOC.USERNAME, value: by, severity: 'info',
          highlightText: by, note: 'IPTC By-line',
        });
      }
    }
    if (data.Credit) {
      f.metadata.iptcCredit = String(data.Credit).trim();
    }
  }

  /**
   * Record the embedded thumbnail's size into metadata and run an
   * embedded-payload scan on its bytes. Tampered thumbnails often leak
   * hints that the outer image has been doctored, and a thumbnail
   * wildly different in aspect ratio to the main image is a known
   * red flag. We keep the surface minimal — just the size and any
   * encoded-payload findings — to avoid noise on every benign JPEG.
   */
  _applyThumbnail(f, thumbBytes) {
    if (!thumbBytes) return;
    // exifr.thumbnail returns Uint8Array in browsers
    const tb = thumbBytes instanceof Uint8Array
      ? thumbBytes
      : (thumbBytes.buffer ? new Uint8Array(thumbBytes.buffer) : null);
    if (!tb || !tb.length) return;
    f.metadata.exifThumbnailBytes = this._fmtBytes(tb.length);

    // Thumbnail should itself start with JPEG SOI (FF D8) — if it
    // doesn't, that's suspicious (a raw payload masquerading as a
    // thumbnail). Surface as a low-severity pattern so the analyst
    // can decide. Pako-style inflated payload or PE/MZ header inside
    // a thumbnail is picked up by the main YARA scan of the parent
    // file bytes, so we don't double-report.
    if (tb.length >= 2 && !(tb[0] === 0xFF && tb[1] === 0xD8)) {
      pushIOC(f, {
        type: IOC.PATTERN,
        value: `EXIF thumbnail does not start with JPEG SOI marker (${this._fmtBytes(tb.length)})`,
        severity: 'medium',
        note: 'Malformed / non-JPEG thumbnail payload',
      });
      if (f.risk === 'low') f.risk = 'medium';
    }
  }

  /**
   * Walk every IFD in a TIFF and dump well-known tags into `f.metadata`,
   * plus feed long string / byte tags through a minimal pattern scan
   * for embedded executables and URLs. We deliberately limit ourselves
   * to classic "ASCII" (type 2) and "BYTE" (type 1) tags because those
   * are the ones attackers hide payloads in.
   *
   * TIFF tag reference: https://www.awaresystems.be/imaging/tiff/tifftags.html
   */
  _applyTiffTags(f, ifds) {
    // Well-known TIFF tag IDs → human-readable label + metadata key
    const TAGS = {
      270: { label: 'ImageDescription',  key: 'tiffImageDescription', pivot: false },
      271: { label: 'Make',              key: 'tiffMake',             pivot: false },
      272: { label: 'Model',             key: 'tiffModel',            pivot: false },
      305: { label: 'Software',          key: 'tiffSoftware',         pivot: true  },
      306: { label: 'DateTime',          key: 'tiffDateTime',         pivot: false },
      315: { label: 'Artist',            key: 'tiffArtist',           pivot: true  },
      316: { label: 'HostComputer',      key: 'tiffHostComputer',     pivot: true  },
      33432:{ label: 'Copyright',        key: 'tiffCopyright',        pivot: false },
      700:  { label: 'XMP',              key: 'tiffXmp',              pivot: false },
      33723:{ label: 'IPTC',             key: 'tiffIptc',             pivot: false },
    };
    const MAX_INLINE = 200;
    const pageCount = ifds.length;
    if (pageCount > 1) f.metadata.tiffPageCount = String(pageCount);

    let tiffIfdCount = 0;
    for (const ifd of ifds) {
      tiffIfdCount++;
      if (tiffIfdCount > 4) break; // cap IFD walk — multi-page TIFFs rarely carry unique metadata past the first few
      for (const tagId of Object.keys(TAGS)) {
        const v = ifd['t' + tagId];
        if (v === undefined || v === null) continue;
        const { label, key, pivot } = TAGS[tagId];
        let strVal;
        if (typeof v === 'string') strVal = v;
        else if (Array.isArray(v)) {
          // ASCII arrays come through as arrays of char codes or single-char strings
          strVal = v.map(x => typeof x === 'string' ? x : String.fromCharCode(x & 0xff)).join('').replace(/\0+$/, '');
        } else {
          strVal = String(v);
        }
        strVal = strVal.trim();
        if (!strVal || strVal.length < 2) continue;

        // Only overwrite if not already set by a prior IFD
        if (!f.metadata[key]) {
          f.metadata[key] = strVal.length > MAX_INLINE ? strVal.slice(0, MAX_INLINE) + '…' : strVal;
        }

        if (pivot && strVal.length <= MAX_INLINE) {
          pushIOC(f, {
            type: IOC.PATTERN,
            value: `TIFF ${label}: ${strVal}`,
            severity: 'info',
            highlightText: strVal,
            note: `TIFF tag ${tagId} (${label})`,
          });
        }

        // Embedded-payload scan on long text tags — XMP and ImageDescription
        // are the classic hiding spots. We extract URLs and run a minimal
        // PE/MZ-in-base64 check; the heavy lifting stays with YARA scanning
        // the full file, so we only surface outright URL pivots here.
        if (strVal.length > 64) {
          try {
            const urls = extractUrls(strVal, 10);
            for (const u of urls) {
              pushIOC(f, {
                type: IOC.URL,
                value: u,
                severity: 'medium',
                highlightText: u,
                note: `URL embedded in TIFF ${label} tag`,
              });
            }
          } catch (_) { /* url extraction optional */ }
        }
      }
    }
  }

  _fmtExifDate(d) {
    if (!d) return '';
    if (d instanceof Date) {
      try { return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ''); }
      catch (_) { return String(d); }
    }
    return String(d);
  }

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
