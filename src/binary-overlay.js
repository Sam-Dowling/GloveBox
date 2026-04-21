// binary-overlay.js — Shared overlay detection + drill-down for native binaries.
//
// An "overlay" is any bytes that live past the declared end-of-image of a
// structured binary. The classic malware play is to staple a second file
// (a ZIP, a 7z, a RAR, a PE dropper, an encrypted blob, …) onto the tail
// of a signed-looking executable — the host OS still runs the EXE
// happily, and the attacker's loader reaches past the structured region
// to pick up its payload. Authenticode-signed installers legitimately
// use the same trick, which is why we special-case the PE certificate
// table below.
//
// Per-format "end of image" (caller's responsibility):
//   PE     → max(section.rawDataOffset + section.rawDataSize)
//            Plus: if dataDirectories[4].size > 0, the Certificate Table
//            at [certOff, certOff + certSize) is the Authenticode blob
//            — overlay that exactly matches the cert range is NOT
//            suspicious; bytes *past* the cert range are the truly
//            anomalous post-sign tail.
//   ELF    → max(sh.offset + sh.size) over section headers where
//            sh.type !== 8 (SHT_NOBITS). Fallback for stripped binaries
//            (no section headers): max(ph.offset + ph.filesz).
//   Mach-O → max(seg.fileoff + seg.filesize). Fat/Universal: compute
//            per-slice overlay within each slice's declared (offset,size).
//
// Contract
// --------
//   BinaryOverlay.compute({ bytes, overlayStart, fileSize })
//     → null                             if overlayStart >= fileSize
//     → { start, end, size, entropy,
//         magic: { label, extHint } | null,
//         sha256Promise }                sha256 is async (crypto.subtle).
//
//   BinaryOverlay.renderCard({
//     bytes, overlayStart, fileSize, baseName,
//     title,                             display label
//     authenticodeRange,                 PE-only: [certOff, certEnd] or null
//     onClick,                           extra callback (optional)
//   }) → HTMLElement
//
//   BinaryOverlay.shannonEntropy(u8)     byte-histogram H, 0..8
//   BinaryOverlay.sniffMagic(u8)         first-bytes → { label, extHint }
//
// The card *itself* never mutates findings. Each renderer decides what
// to push onto `interestingStrings` / `externalRefs` / `findings.metadata`
// and how much to bump `riskScore`. That keeps capability-of-concern
// logic inside the renderer that owns the format.

const BinaryOverlay = (() => {

  // Cap entropy sampling so a multi-GiB installer doesn't freeze the tab.
  // Matches the spirit of parser-watchdog: bounded, best-effort, always
  // returns a number. We sample ~2 MiB in two evenly-spaced windows (head
  // and tail) since high-entropy regions tend to sit at either end of an
  // appended payload (compressed archive header + trailer); the midsection
  // is usually uniform noise and adding more samples doesn't change H
  // meaningfully for the triage question "is this a packed blob?".
  const ENTROPY_SAMPLE_CAP = 2 * 1024 * 1024;

  // ── Shannon entropy ──────────────────────────────────────────────────────
  function shannonEntropy(u8) {
    if (!u8 || u8.length === 0) return 0;
    let view = u8;
    if (u8.length > ENTROPY_SAMPLE_CAP) {
      const half = ENTROPY_SAMPLE_CAP >>> 1;
      const head = u8.subarray(0, half);
      const tail = u8.subarray(u8.length - half);
      view = new Uint8Array(ENTROPY_SAMPLE_CAP);
      view.set(head, 0);
      view.set(tail, half);
    }
    const freq = new Uint32Array(256);
    for (let i = 0; i < view.length; i++) freq[view[i]]++;
    const n = view.length;
    let H = 0;
    for (let i = 0; i < 256; i++) {
      if (freq[i] === 0) continue;
      const p = freq[i] / n;
      H -= p * Math.log2(p);
    }
    return Math.round(H * 1000) / 1000;
  }

  // ── First-bytes magic sniff ──────────────────────────────────────────────
  // Not a substitute for RendererRegistry.detect — just picks a filename
  // extension hint for the synthetic File so the registry routes to the
  // right renderer on click. The registry itself does the real detection
  // on reload.
  function sniffMagic(u8) {
    if (!u8 || u8.length < 2) return null;
    const b = u8;
    const b0 = b[0], b1 = b[1], b2 = b.length > 2 ? b[2] : 0, b3 = b.length > 3 ? b[3] : 0;

    // PE (MZ) — appended executable, classic dropper
    if (b0 === 0x4D && b1 === 0x5A) return { label: 'PE (MZ)', extHint: '.exe' };
    // ELF
    if (b0 === 0x7F && b1 === 0x45 && b2 === 0x4C && b3 === 0x46) return { label: 'ELF', extHint: '.elf' };
    // Mach-O (both endians, both bitnesses)
    if (b0 === 0xCF && b1 === 0xFA && b2 === 0xED && b3 === 0xFE) return { label: 'Mach-O', extHint: '.macho' };
    if (b0 === 0xCE && b1 === 0xFA && b2 === 0xED && b3 === 0xFE) return { label: 'Mach-O', extHint: '.macho' };
    if (b0 === 0xFE && b1 === 0xED && b2 === 0xFA && b3 === 0xCF) return { label: 'Mach-O', extHint: '.macho' };
    if (b0 === 0xFE && b1 === 0xED && b2 === 0xFA && b3 === 0xCE) return { label: 'Mach-O', extHint: '.macho' };
    if (b0 === 0xCA && b1 === 0xFE && b2 === 0xBA && b3 === 0xBE) return { label: 'Fat Mach-O / Java class', extHint: '.macho' };

    // ZIP / OOXML / APK / JAR / CRX(raw) — PK\x03\x04 + PK\x05\x06 empty + PK\x07\x08 spanned
    if (b0 === 0x50 && b1 === 0x4B && (b2 === 0x03 || b2 === 0x05 || b2 === 0x07)) return { label: 'ZIP / PK', extHint: '.zip' };
    // 7z
    if (b0 === 0x37 && b1 === 0x7A && b2 === 0xBC && b3 === 0xAF && b.length > 5 && b[4] === 0x27 && b[5] === 0x1C) return { label: '7-Zip', extHint: '.7z' };
    // RAR v4/v5 — "Rar!\x1A\x07\x00" / "Rar!\x1A\x07\x01\x00"
    if (b0 === 0x52 && b1 === 0x61 && b2 === 0x72 && b3 === 0x21 && b.length > 5 && b[4] === 0x1A && b[5] === 0x07) return { label: 'RAR', extHint: '.rar' };
    // Gzip
    if (b0 === 0x1F && b1 === 0x8B) return { label: 'gzip', extHint: '.gz' };
    // bzip2
    if (b0 === 0x42 && b1 === 0x5A && b2 === 0x68) return { label: 'bzip2', extHint: '.bz2' };
    // xz
    if (b0 === 0xFD && b1 === 0x37 && b2 === 0x7A && b3 === 0x58 && b.length > 5 && b[4] === 0x5A && b[5] === 0x00) return { label: 'xz', extHint: '.xz' };
    // zstd
    if (b0 === 0x28 && b1 === 0xB5 && b2 === 0x2F && b3 === 0xFD) return { label: 'zstd', extHint: '.zst' };
    // CAB (MSCF)
    if (b0 === 0x4D && b1 === 0x53 && b2 === 0x43 && b3 === 0x46) return { label: 'CAB (MSCF)', extHint: '.cab' };
    // MSI / OLE CFB (D0 CF 11 E0 A1 B1 1A E1)
    if (b0 === 0xD0 && b1 === 0xCF && b2 === 0x11 && b3 === 0xE0) return { label: 'OLE CFB (MSI / Office)', extHint: '.msi' };

    // PDF
    if (b0 === 0x25 && b1 === 0x50 && b2 === 0x44 && b3 === 0x46) return { label: 'PDF', extHint: '.pdf' };
    // PNG / JPEG / GIF — appended image payloads are a known steganography trick
    if (b0 === 0x89 && b1 === 0x50 && b2 === 0x4E && b3 === 0x47) return { label: 'PNG', extHint: '.png' };
    if (b0 === 0xFF && b1 === 0xD8 && b2 === 0xFF) return { label: 'JPEG', extHint: '.jpg' };
    if (b0 === 0x47 && b1 === 0x49 && b2 === 0x46 && b3 === 0x38) return { label: 'GIF', extHint: '.gif' };

    // Shebang script
    if (b0 === 0x23 && b1 === 0x21) return { label: 'Shebang script', extHint: '.sh' };
    // XML / plist (ASCII "<?xml" or "<plist")
    if (b0 === 0x3C && b1 === 0x3F && b2 === 0x78 && b3 === 0x6D) return { label: 'XML', extHint: '.xml' };

    // ASN.1 DER SEQUENCE — PKCS#7 / Authenticode blob signature
    if (b0 === 0x30 && (b1 === 0x82 || b1 === 0x83 || b1 === 0x84)) return { label: 'ASN.1 DER (PKCS#7 / cert)', extHint: '.der' };

    return null;
  }

  // ── SHA-256 via crypto.subtle ────────────────────────────────────────────
  // Loupe's CSP is `default-src 'none'` — crypto.subtle is part of the page
  // origin and is explicitly allowed. Returns a Promise for a lowercase hex
  // string. Wrapped in a function so callers can `await` OR `.then()`
  // without reaching into the subtle API themselves.
  async function sha256Hex(u8) {
    try {
      // crypto.subtle wants a fresh buffer, not a subarray view with offset.
      const view = (u8.byteOffset === 0 && u8.byteLength === u8.buffer.byteLength)
        ? u8.buffer
        : u8.slice().buffer;
      const digest = await crypto.subtle.digest('SHA-256', view);
      const bytes = new Uint8Array(digest);
      let hex = '';
      for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
      return hex;
    } catch (_) {
      return null;
    }
  }

  // ── Compute overlay summary ──────────────────────────────────────────────
  /**
   * @param {{ bytes: Uint8Array, overlayStart: number, fileSize: number }} opts
   * @returns {null | {
   *   start: number, end: number, size: number,
   *   entropy: number,
   *   magic: { label: string, extHint: string } | null,
   *   sha256Promise: Promise<string|null>,
   * }}
   */
  function compute({ bytes, overlayStart, fileSize }) {
    if (!bytes || !Number.isFinite(overlayStart) || !Number.isFinite(fileSize)) return null;
    if (overlayStart < 0) overlayStart = 0;
    if (fileSize > bytes.length) fileSize = bytes.length;
    if (overlayStart >= fileSize) return null;

    const view = bytes.subarray(overlayStart, fileSize);
    const magic = sniffMagic(view.subarray(0, 32));
    const entropy = shannonEntropy(view);
    // Hash is fire-and-forget from the caller's perspective — the card
    // replaces its placeholder row when it settles.
    const sha256Promise = sha256Hex(view);

    return {
      start: overlayStart,
      end: fileSize,
      size: fileSize - overlayStart,
      entropy,
      magic,
      sha256Promise,
    };
  }

  // ── UI helpers ───────────────────────────────────────────────────────────
  function _fmtBytes(n) {
    if (typeof fmtBytes === 'function') return fmtBytes(n);
    // Minimal fallback (fmtBytes is in constants.js; shouldn't ever miss,
    // but keeping the helper self-contained avoids a load-order surprise).
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB';
    return (n / 1024 / 1024 / 1024).toFixed(2) + ' GB';
  }

  function _esc(s) {
    if (typeof escHtml === 'function') return escHtml(s);
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  /**
   * Build the overlay drill-down card DOM.
   *
   * @param {{
   *   bytes: Uint8Array,
   *   overlayStart: number,
   *   fileSize: number,
   *   baseName: string,
   *   subtitle?: string,                 caller-supplied context line
   *   authenticodeRange?: [number, number] | null,
   *   onHash?: (hex: string) => void,    fires once SHA-256 settles
   * }} opts
   * @returns {{ el: HTMLElement, info: ReturnType<typeof compute> | null }}
   */
  function renderCard(opts) {
    const { bytes, overlayStart, fileSize, baseName } = opts;
    const info = compute({ bytes, overlayStart, fileSize });
    const box = document.createElement('div');
    box.className = 'binary-overlay-card';
    if (!info) {
      // Caller can choose to skip rendering; we still return an empty shell
      // so they don't have to null-check.
      return { el: box, info: null };
    }

    const overlayBytes = bytes.subarray(info.start, info.end);

    // Authenticode awareness (PE only). If the overlay span is exactly the
    // cert table, that's a normal signed binary → neutral rendering. If
    // there are bytes past the cert table, those are the real overlay and
    // we keep the standard "click to re-analyse" behaviour.
    let postAuthenticode = false;
    let overlayIsJustAuthenticode = false;
    if (opts.authenticodeRange && Array.isArray(opts.authenticodeRange) && opts.authenticodeRange.length === 2) {
      const [certOff, certEnd] = opts.authenticodeRange;
      if (info.start === certOff && info.end === certEnd) {
        overlayIsJustAuthenticode = true;
      } else if (certEnd > 0 && info.end > certEnd && info.start <= certEnd) {
        postAuthenticode = true;
      }
    }

    // ── Header row ────────────────────────────────────────────────────────
    const pct = (info.size / Math.max(1, fileSize)) * 100;
    const title = opts.subtitle
      ? `Overlay · ${_esc(opts.subtitle)}`
      : 'Overlay';
    const header = document.createElement('div');
    header.className = 'binary-overlay-head';
    const magicLabel = info.magic
      ? `<span class="doc-meta-tag">${_esc(info.magic.label)}</span>`
      : `<span class="doc-meta-tag">unrecognised</span>`;
    const sigTag = overlayIsJustAuthenticode
      ? ` <span class="doc-meta-tag">Authenticode signature</span>`
      : postAuthenticode
        ? ` <span class="doc-meta-tag risk-critical">Post-signature tail</span>`
        : '';
    header.innerHTML =
      `<strong>${_esc(title)}</strong> ` +
      `<span class="doc-meta-tag">${_fmtBytes(info.size)} (${pct.toFixed(1)}%)</span> ` +
      `<span class="doc-meta-tag">entropy ${info.entropy.toFixed(2)}</span> ` +
      magicLabel + sigTag;
    box.appendChild(header);

    // ── Detail rows ───────────────────────────────────────────────────────
    const detail = document.createElement('div');
    detail.className = 'binary-overlay-detail';
    const offHex = '0x' + info.start.toString(16).toUpperCase();
    const endHex = '0x' + info.end.toString(16).toUpperCase();
    const shaRow = document.createElement('div');
    shaRow.className = 'binary-overlay-sha';
    shaRow.textContent = 'SHA-256: computing…';
    detail.innerHTML =
      `<div>Offset: <code>${offHex}</code> – <code>${endHex}</code></div>` +
      `<div>Magic: ${info.magic ? _esc(info.magic.label) : '(unrecognised / high-entropy)'}</div>`;
    detail.appendChild(shaRow);
    box.appendChild(detail);

    info.sha256Promise.then(hex => {
      if (hex) {
        shaRow.innerHTML = `SHA-256: <code>${_esc(hex)}</code>`;
        if (typeof opts.onHash === 'function') {
          try { opts.onHash(hex); } catch (_) { /* host callback best-effort */ }
        }
      } else {
        shaRow.textContent = 'SHA-256: unavailable';
      }
    });

    // ── Re-dispatch button ────────────────────────────────────────────────
    // Signature-only overlays (PE Authenticode blob that exactly matches
    // the cert table) are kept non-clickable — dispatching would route the
    // raw PKCS#7 to x509-renderer which is handled separately in the
    // Certificates section, and clicking would create confusing nav history.
    if (!overlayIsJustAuthenticode) {
      const actions = document.createElement('div');
      actions.className = 'binary-overlay-actions';
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'tb-btn';
      btn.textContent = 'Analyse overlay as a fresh file →';
      btn.title = 'Extract these bytes and route them through Loupe\'s renderer registry';
      btn.addEventListener('click', () => {
        const safeBase = String(baseName || 'overlay').replace(/[<>:"/\\|?*\x00-\x1f]/g, '_');
        const ext = (info.magic && info.magic.extHint) || '.bin';
        const fname = `${safeBase}.overlay${ext}`;
        const f = new File([overlayBytes], fname, { type: 'application/octet-stream' });
        // Bubble so the PE/ELF/Mach-O wrap (or any ancestor wired by
        // _wireInnerFileListener in app-load.js) catches it.
        box.dispatchEvent(new CustomEvent('open-inner-file', { bubbles: true, detail: f }));
      });
      actions.appendChild(btn);
      box.appendChild(actions);
    }

    return { el: box, info };
  }

  return { compute, renderCard, shannonEntropy, sniffMagic, sha256Hex };
})();

if (typeof window !== 'undefined') window.BinaryOverlay = BinaryOverlay;
