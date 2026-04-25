'use strict';
// ════════════════════════════════════════════════════════════════════════════
// dmg-renderer.js — Apple Disk Image (.dmg / UDIF) analyser
//
// A DMG is a UDIF (Universal Disk Image Format) container: raw or
// compressed block data at the front, followed by a 512-byte 'koly' trailer
// at the very end of the file. The trailer points to an XML plist that
// enumerates the image's partitions as a 'blkx' array of base64-encoded
// mish blocks. See Apple TN2166 and the open-source `dmg2img` reverse
// engineering for the byte layout.
//
// In-browser, we do NOT attempt to mount the HFS+/APFS volume inside the
// image — that requires a full filesystem parser and gigabytes of runtime.
// Instead we surface:
//
//   • UDIF header fields (image size, sector count, encrypted bit, SLA)
//   • Partition table (name, block-type mix, size, checksum)
//   • Best-effort string scan for .app bundles, Info.plist fragments, URLs
//   • Whether the image looks like a drag-to-Applications phishing shape
//     (the classic macOS malware social-engineering delivery)
//
// Depends on: constants.js (IOC, escHtml, fmtBytes, extractAsciiAndUtf16leStrings)
// ════════════════════════════════════════════════════════════════════════════

class DmgRenderer {

  // UDIF image type codes (from koly trailer offset +60)
  static IMAGE_TYPES = Object.freeze({
    1:  'Device image',
    2:  'Partition image',
    16: 'Device image (disk image 2)',
  });

  // UDIF image-flags bitfield (koly +124)
  static IMAGE_FLAGS = Object.freeze([
    { mask: 0x00000001, label: 'Flattened' },
    { mask: 0x00000002, label: 'Internet-enabled' },
    { mask: 0x00000004, label: 'Raw image' },
    // Encrypted DMGs use a distinct envelope ("encrcdsa" / "cdsaencr") —
    // we detect that separately below, but if a producer ever sets the
    // flag we'll report it too.
  ]);

  // mish block types (inside each BLKX blob)
  static BLOCK_TYPES = Object.freeze({
    0x00000000: 'zero fill',
    0x00000001: 'raw',
    0x00000002: 'ignored',
    0x80000004: 'comment',
    0x80000005: 'ADC',
    0x80000006: 'zlib',
    0x80000007: 'bzip2',
    0x80000008: 'lzfse',
    0x80000009: 'lzma',
    0xFFFFFFFF: 'terminator',
  });

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const wrap = document.createElement('div'); wrap.className = 'iso-view dmg-view';

    // Banner
    const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
    banner.innerHTML = '<strong>Apple Disk Image (.dmg)</strong> — UDIF container. ' +
      'DMGs are the standard macOS phishing delivery vehicle and bypass Mark-of-the-Web on the target host.';
    wrap.appendChild(banner);

    // Detect encrypted DMG (different container — no koly trailer)
    const encEnvelope = this._detectEncrypted(bytes);
    if (encEnvelope) {
      const vol = document.createElement('div'); vol.className = 'iso-volume-info';
      vol.innerHTML = `<strong>Encrypted DMG</strong> · ${escHtml(encEnvelope)} envelope · ` +
        `<strong>Size:</strong> ${this._fmtBytes(bytes.length)}`;
      wrap.appendChild(vol);

      const warnDiv = document.createElement('div'); warnDiv.className = 'zip-warnings';
      const d = document.createElement('div'); d.className = 'zip-warning zip-warning-high';
      d.textContent = '🔒 Encrypted disk image — contents cannot be inspected without the passphrase.';
      warnDiv.appendChild(d); wrap.appendChild(warnDiv);
      return wrap;
    }

    // Parse koly trailer
    let udif;
    try {
      udif = this._parseKoly(bytes);
    } catch (e) {
      const p = document.createElement('p'); p.style.cssText = 'color:var(--risk-high);padding:20px';
      p.textContent = `Could not parse UDIF trailer: ${e.message}`;
      wrap.appendChild(p);
      return wrap;
    }

    // Volume info line
    const vol = document.createElement('div'); vol.className = 'iso-volume-info';
    const typeLabel = DmgRenderer.IMAGE_TYPES[udif.imageType] || `type ${udif.imageType}`;
    vol.innerHTML = `<strong>Type:</strong> ${escHtml(typeLabel)} &nbsp;·&nbsp; ` +
      `<strong>Sectors:</strong> ${udif.sectorCount.toLocaleString()} &nbsp;·&nbsp; ` +
      `<strong>Size:</strong> ${this._fmtBytes(bytes.length)} &nbsp;·&nbsp; ` +
      `<strong>Checksum:</strong> ${escHtml(this._checksumName(udif.checksumType))}`;
    wrap.appendChild(vol);

    // Parse embedded XML plist (blkx table)
    const parts = this._parsePartitions(bytes, udif);
    const strings = this._scanStrings(bytes);

    const summ = document.createElement('div'); summ.className = 'zip-summary';
    summ.textContent = `${parts.length} partition(s) · ${strings.apps.length} app bundle path(s) · xml plist ${this._fmtBytes(udif.xmlLength)}`;
    wrap.appendChild(summ);

    // Warnings
    const warnings = this._checkWarnings(udif, parts, strings);
    if (warnings.length) {
      const warnDiv = document.createElement('div'); warnDiv.className = 'zip-warnings';
      for (const w of warnings) {
        const d = document.createElement('div'); d.className = `zip-warning zip-warning-${w.sev}`;
        d.textContent = w.msg; warnDiv.appendChild(d);
      }
      wrap.appendChild(warnDiv);
    }

    // UDIF header table
    const hdr = document.createElement('table'); hdr.className = 'lnk-info-table';
    hdr.style.cssText = 'margin:4px 20px 12px;';
    const addRow = (k, v) => {
      const tr = document.createElement('tr');
      const tdL = document.createElement('td'); tdL.className = 'lnk-lbl'; tdL.textContent = k;
      const tdV = document.createElement('td'); tdV.className = 'lnk-val'; tdV.textContent = v;
      tr.appendChild(tdL); tr.appendChild(tdV); hdr.appendChild(tr);
    };
    addRow('UDIF version',     String(udif.version));
    addRow('Data fork',        `offset ${udif.dataForkOffset}, length ${this._fmtBytes(udif.dataForkLength)}`);
    addRow('XML plist',        `offset ${udif.xmlOffset}, length ${this._fmtBytes(udif.xmlLength)}`);
    addRow('Resource fork',    udif.rsrcForkLength ? `offset ${udif.rsrcForkOffset}, length ${this._fmtBytes(udif.rsrcForkLength)}` : '(none)');
    addRow('Flags',            this._flagsLabel(udif.flags));
    wrap.appendChild(hdr);

    // Partition table
    if (parts.length) {
      const h = document.createElement('div'); h.className = 'hta-section-hdr';
      h.textContent = `Partitions (${parts.length})`; wrap.appendChild(h);

      const scr = document.createElement('div'); scr.style.cssText = 'overflow:auto;max-height:40vh;margin:0 20px 12px';
      const tbl = document.createElement('table'); tbl.className = 'zip-table';
      const thead = document.createElement('thead');
      const hr = document.createElement('tr');
      for (const cap of ['Partition', 'Sectors', 'Uncompressed', 'Compression mix']) {
        const th = document.createElement('th'); th.textContent = cap; hr.appendChild(th);
      }
      thead.appendChild(hr); tbl.appendChild(thead);
      const tbody = document.createElement('tbody');
      for (const p of parts) {
        const tr = document.createElement('tr');
        const tdN = document.createElement('td'); tdN.className = 'zip-path'; tdN.textContent = p.name || '(unnamed)';
        tr.appendChild(tdN);
        const tdS = document.createElement('td'); tdS.className = 'zip-size'; tdS.textContent = p.sectorCount.toLocaleString();
        tr.appendChild(tdS);
        const tdB = document.createElement('td'); tdB.className = 'zip-size'; tdB.textContent = this._fmtBytes(p.sectorCount * 512);
        tr.appendChild(tdB);
        const tdC = document.createElement('td'); tdC.className = 'zip-date'; tdC.textContent = p.compressionMix || '—';
        tr.appendChild(tdC);
        tbody.appendChild(tr);
      }
      tbl.appendChild(tbody); scr.appendChild(tbl); wrap.appendChild(scr);
    }

    // String scan: .app bundle paths are the single most useful SOC
    // artefact inside a DMG. Filesystem parsing is out of scope, but the
    // HFS+ catalog file leaves ASCII filename fragments we can fish out.
    if (strings.apps.length) {
      const h = document.createElement('div'); h.className = 'hta-section-hdr';
      h.textContent = `Detected .app bundle paths (${strings.apps.length})`; wrap.appendChild(h);
      const list = document.createElement('ul');
      list.style.cssText = 'margin:0 20px 12px;padding-left:24px;font-family:monospace;font-size:12px;';
      for (const path of strings.apps.slice(0, 40)) {
        const li = document.createElement('li'); li.textContent = path; list.appendChild(li);
      }
      if (strings.apps.length > 40) {
        const li = document.createElement('li'); li.textContent = `… ${strings.apps.length - 40} more`;
        li.style.color = 'var(--muted-text, #888)'; list.appendChild(li);
      }
      wrap.appendChild(list);
    }

    // Embedded SLA (software license agreement) — normal for signed DMGs
    // but its absence on an executable-laden image is notable.
    if (udif.hasSla) {
      const note = document.createElement('p');
      note.style.cssText = 'margin:4px 20px 12px;font-size:12px;color:var(--muted-text, #888);';
      note.textContent = 'DMG carries a Software License Agreement block (shown by Finder before mount).';
      wrap.appendChild(note);
    }

    return wrap;
  }

  // ── Security analysis ─────────────────────────────────────────────────────

  analyzeForSecurity(buffer, fileName) {
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: []
    };
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);

    // DMG baseline (mirrors ISO: bypasses Mark-of-the-Web once mounted)
    f.externalRefs.push({
      type: IOC.PATTERN,
      url: 'Disk image file — bypasses Mark-of-the-Web (MOTW) protection on macOS',
      severity: 'medium'
    });

    // Encrypted shell?
    const envelope = this._detectEncrypted(bytes);
    if (envelope) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `Encrypted DMG (${envelope}) — contents not inspectable without passphrase`,
        severity: 'high'
      });
      escalateRisk(f, 'high');
      f.metadata = { title: '(encrypted DMG)', subject: this._fmtBytes(bytes.length) };
      return f;
    }

    let udif;
    try { udif = this._parseKoly(bytes); } catch (e) { return f; }

    const parts = this._parsePartitions(bytes, udif);
    const strings = this._scanStrings(bytes);

    f.metadata = {
      title:   parts[0]?.name || '',
      creator: `UDIF v${udif.version}`,
      subject: `${parts.length} partition(s) · ${this._fmtBytes(bytes.length)}`,
    };

    // .app bundle inside DMG is the heart of macOS drop-delivery phishing.
    // Cap emission to keep the sidebar usable — emit a visible IOC.INFO
    // truncation marker when we hit the ceiling so the analyst isn't
    // misled into thinking the list is complete.
    const APP_IOC_CAP = 100;
    if (strings.apps.length) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `${strings.apps.length} application bundle path(s) inside disk image`,
        severity: 'high'
      });
      escalateRisk(f, 'high');
      for (const path of strings.apps.slice(0, APP_IOC_CAP)) {
        f.externalRefs.push({ type: IOC.FILE_PATH, url: path, severity: 'high' });
      }
      if (strings.apps.length > APP_IOC_CAP) {
        f.externalRefs.push({
          type: IOC.INFO,
          url: `… ${strings.apps.length - APP_IOC_CAP} additional .app bundle path(s) not shown (IOC cap ${APP_IOC_CAP})`,
          severity: 'info'
        });
      }
    }

    // "Drag-to-Applications" phishing shape: Applications symlink + .app
    if (strings.hasApplicationsSymlink && strings.apps.length) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: 'DMG contains both an Applications symlink and a .app bundle — classic drag-to-install social-engineering shape',
        severity: 'high'
      });
      escalateRisk(f, 'high');
    }

    // Hidden .app (leading dot) — staple of macOS trojans
    const hidden = strings.apps.filter(a => /(^|\/)\./.test(a));
    if (hidden.length) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `${hidden.length} hidden .app bundle(s) inside disk image`,
        severity: 'high'
      });
      escalateRisk(f, 'high');
    }

    // URLs surfaced from the image (Info.plist, license text)
    const seenUrl = new Set();
    let urlCount = 0, urlTrunc = false;
    for (const u of strings.urls) {
      if (seenUrl.has(u)) continue; seenUrl.add(u);
      // Anchor the host check to the URL's hostname so "evil-apple.com.bad.example"
      // isn't silently whitelisted as an apple.com URL by a substring match.
      if (this._isAppleHost(u)) continue;
      f.externalRefs.push({ type: IOC.URL, url: u, severity: 'info' });
      urlCount++;
      if (f.externalRefs.length > 200) { urlTrunc = true; break; }
    }
    if (urlTrunc) {
      f.externalRefs.push({
        type: IOC.INFO,
        url: `URL harvest truncated at ${urlCount} — additional URLs present but not emitted (IOC cap reached)`,
        severity: 'info'
      });
    }

    return f;
  }

  // ── UDIF koly trailer parse ───────────────────────────────────────────────

  _parseKoly(bytes) {
    if (bytes.length < 512) throw new Error('file smaller than UDIF trailer');
    const off = bytes.length - 512;
    // Magic: 'koly' = 0x6B 0x6F 0x6C 0x79
    if (!(bytes[off] === 0x6B && bytes[off + 1] === 0x6F
       && bytes[off + 2] === 0x6C && bytes[off + 3] === 0x79)) {
      throw new Error("missing 'koly' magic at end of file");
    }

    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    // Fields are big-endian (UDIF is BE).
    // Layout taken from Apple's disk-image utilities source & dmg2img:
    //   off+0   magic 'koly'
    //   off+4   uint32  version
    //   off+8   uint32  headerSize (always 512)
    //   off+12  uint32  flags
    //   off+16  uint64  runningDataForkOffset
    //   off+24  uint64  dataForkOffset
    //   off+32  uint64  dataForkLength
    //   off+40  uint64  rsrcForkOffset
    //   off+48  uint64  rsrcForkLength
    //   off+56  uint32  segmentNumber
    //   off+60  uint32  segmentCount
    //   off+64  16B     segmentID (uuid)
    //   off+80  uint32  dataForkChecksumType
    //   off+84  uint32  dataForkChecksumSize
    //   off+88  128B    dataForkChecksumData
    //   off+216 uint64  xmlOffset
    //   off+224 uint64  xmlLength
    //   off+232 120B    reserved
    //   off+352 uint32  masterChecksumType
    //   off+356 uint32  masterChecksumSize
    //   off+360 128B    masterChecksumData
    //   off+488 uint32  imageVariant
    //   off+492 uint64  sectorCount
    const u32 = (o) => dv.getUint32(off + o, false);
    const u64 = (o) => Number(dv.getBigUint64(off + o, false));

    const version          = u32(4);
    const flags            = u32(12);
    const dataForkOffset   = u64(24);
    const dataForkLength   = u64(32);
    const rsrcForkOffset   = u64(40);
    const rsrcForkLength   = u64(48);
    const checksumType     = u32(80);
    const xmlOffset        = u64(216);
    const xmlLength        = u64(224);
    const imageVariant     = u32(488);
    const sectorCount      = u64(492);
    // "imageType" isn't a field name in the canonical spec but we
    // synthesise one from imageVariant for the UI.
    const imageType        = imageVariant;

    // SLA (software license agreement) hint — the resource fork carries
    // a 'LPic' resource when present. Cheap check: look for 'LPic' in
    // the resource fork range.
    let hasSla = false;
    if (rsrcForkLength > 0 && rsrcForkOffset + rsrcForkLength <= bytes.length) {
      const slice = bytes.subarray(rsrcForkOffset, rsrcForkOffset + Math.min(rsrcForkLength, 65536));
      hasSla = this._contains(slice, [0x4C, 0x50, 0x69, 0x63]); // 'LPic'
    }

    return {
      version, flags,
      dataForkOffset, dataForkLength,
      rsrcForkOffset, rsrcForkLength,
      checksumType, xmlOffset, xmlLength,
      imageVariant, imageType, sectorCount,
      hasSla,
      trailerOffset: off,
    };
  }

  _parsePartitions(bytes, udif) {
    const parts = [];
    if (!udif.xmlLength || udif.xmlOffset + udif.xmlLength > bytes.length) return parts;

    const xml = new TextDecoder('utf-8', { fatal: false })
      .decode(bytes.subarray(udif.xmlOffset, udif.xmlOffset + udif.xmlLength));

    // Each blkx entry is a <dict> under <key>blkx</key><array>…</array> with
    // a <key>Name</key><string>…</string> (human label) and a
    // <key>Data</key><data>…</data> carrying a base64-encoded mish block.
    // Capture the whole dict body so we can pull both fields from *inside*
    // the entry — matching only "before the dict" picks up the previous
    // entry's Name on the 2nd+ iteration.
    const dictRe = /<dict>([\s\S]*?)<\/dict>/g;
    const nameRe   = /<key>\s*Name\s*<\/key>\s*<string>([^<]*)<\/string>/;
    const cfNameRe = /<key>\s*CFName\s*<\/key>\s*<string>([^<]*)<\/string>/;
    const dataRe   = /<key>\s*Data\s*<\/key>\s*<data>([\s\S]*?)<\/data>/;

    let m;
    while ((m = dictRe.exec(xml)) !== null && parts.length < 64) {
      const body = m[1];
      // Only dicts that carry a <data> blob are blkx entries — skip the
      // outer <dict>s that just hold the blkx array itself.
      const dm = dataRe.exec(body);
      if (!dm) continue;

      let name = '';
      const nm = nameRe.exec(body);
      if (nm) name = nm[1].trim();
      if (!name) {
        const cm = cfNameRe.exec(body);
        if (cm) name = cm[1].trim();
      }

      // Decode the base64 mish block to get block-type counts and sector totals
      const mish = this._decodeBase64(dm[1].replace(/\s+/g, ''));
      if (!mish || mish.length < 204) {
        parts.push({ name, sectorCount: 0, compressionMix: '(unparsed)' });
        continue;
      }
      parts.push(this._parseMishBlock(mish, name));
    }
    return parts;
  }

  _parseMishBlock(mish, name) {
    // BLKX mish header layout (big-endian), per Apple's DiskImages.framework
    // and dmg2img:
    //   0   uint32   signature 'mish' (0x6D697368)
    //   4   uint32   info version (1)
    //   8   uint64   sector number (start, in image-global sectors)
    //   16  uint64   sector count
    //   24  uint64   data offset (within the data fork)
    //   32  uint32   buffers needed
    //   36  uint32   block descriptor count (informational)
    //   40  24B      reserved (6 × uint32)
    //   64  UDIFChecksum: uint32 type + uint32 size + 128B data = 136B
    //   200 uint32   number of block chunks
    //   204 ...      40-byte BLKX chunk entries (type, comment, sector start,
    //                sector count, compOffset, compLength)
    const dv = new DataView(mish.buffer, mish.byteOffset, mish.byteLength);
    if (dv.getUint32(0, false) !== 0x6D697368) {
      return { name, sectorCount: 0, compressionMix: '(not a mish block)' };
    }
    const sectorCount = Number(dv.getBigUint64(16, false));
    const blockCount  = dv.getUint32(200, false);

    const counts = new Map();
    let pos = 204;
    for (let i = 0; i < blockCount && pos + 40 <= mish.length; i++) {
      const type = dv.getUint32(pos, false);
      const label = DmgRenderer.BLOCK_TYPES[type] || `0x${type.toString(16)}`;
      counts.set(label, (counts.get(label) || 0) + 1);
      pos += 40;
    }

    const mixParts = [];
    for (const [k, v] of counts.entries()) mixParts.push(`${k}×${v}`);
    const compressionMix = mixParts.join(', ');

    return { name, sectorCount, compressionMix };
  }

  // ── Encrypted DMG detection ────────────────────────────────────────────────

  _detectEncrypted(bytes) {
    if (bytes.length < 8) return null;
    // AEA encrypted disk image: 'AEA1' magic at offset 0 (new format)
    if (bytes[0] === 0x41 && bytes[1] === 0x45 && bytes[2] === 0x41 && bytes[3] === 0x31) {
      return 'AEA1';
    }
    // Legacy 'encrcdsa' envelope at offset 0
    const head = String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]);
    if (head === 'encrcdsa') return 'encrcdsa';
    if (head === 'cdsaencr') return 'cdsaencr';
    return null;
  }

  // ── String scanning ───────────────────────────────────────────────────────

  _scanStrings(bytes) {
    // .app bundle directory entries appear as HFS+ catalog nodes scattered
    // through the raw image. We can't parse the catalog without decoding
    // every block, but the ASCII filenames survive — extract every printable
    // run of length ≥ 4 and filter by path shape.
    const { ascii } = (typeof extractAsciiAndUtf16leStrings === 'function')
      ? extractAsciiAndUtf16leStrings(bytes, { asciiMin: 5, utf16Min: 5, cap: 20000 })
      : { ascii: this._fallbackAsciiScan(bytes) };

    // Tight .app regex: must start with an alphanumeric (no leading dots,
    // spaces or hyphens to cut HFS+ padding noise), allows a single
    // internal dot before `.app`, rejects the bare literal ".app" and
    // runs of two+ consecutive spaces — all of which are catalog slack.
    const appRe      = /(?:^|[\s\/"'])([A-Za-z0-9][A-Za-z0-9 _\-]{2,63}(?:\.[A-Za-z0-9 _\-]{1,40})?\.app)\b/g;
    const urlRe      = /https?:\/\/[^\s"'<>]+/g;
    const apps = new Set();
    const urls = new Set();
    let hasApplicationsSymlink = false;

    for (const s of ascii) {
      let m;
      appRe.lastIndex = 0;
      while ((m = appRe.exec(s)) !== null) {
        const hit = m[1];
        // Skip noise: names with runs of 2+ spaces (HFS+ padding artefact)
        // or that are just "<word>.app" where <word> is a common filesystem
        // keyword like "Resources".
        if (/  /.test(hit)) continue;
        if (hit.length >= 5 && hit.length <= 120) apps.add(hit);
      }
      urlRe.lastIndex = 0;
      // urlRe has no capture group — the whole match (m[0]) is the URL.
      while ((m = urlRe.exec(s)) !== null) urls.add(m[0]);
      if (/^Applications$/.test(s.trim())) hasApplicationsSymlink = true;
    }

    return {
      apps: Array.from(apps).slice(0, 400),
      urls: Array.from(urls).slice(0, 400),
      hasApplicationsSymlink,
    };
  }

  _fallbackAsciiScan(bytes) {
    // Very cheap fallback if the shared helper isn't available.
    const out = [];
    let run = '';
    const cap = Math.min(bytes.length, 50 * 1024 * 1024);
    for (let i = 0; i < cap; i++) {
      const b = bytes[i];
      if (b >= 0x20 && b <= 0x7e) { run += String.fromCharCode(b); continue; }
      if (run.length >= 5) out.push(run);
      run = '';
      if (out.length > 20000) break;
    }
    if (run.length >= 5) out.push(run);
    return out;
  }

  // ── UI + helpers ──────────────────────────────────────────────────────────

  _checkWarnings(udif, parts, strings) {
    const w = [];
    if (strings.apps.length) {
      w.push({
        sev: 'high',
        msg: `⚠ ${strings.apps.length} .app bundle(s) detected inside disk image — macOS drop-delivery phishing shape`,
      });
    }
    if (strings.hasApplicationsSymlink && strings.apps.length) {
      w.push({
        sev: 'high',
        msg: '⚠ DMG contains both an Applications symlink and .app bundles — classic drag-to-install trojan layout',
      });
    }
    const hidden = strings.apps.filter(a => /(^|\/)\./.test(a));
    if (hidden.length) {
      w.push({
        sev: 'high',
        msg: `⚠ ${hidden.length} hidden .app bundle(s) (leading dot) inside disk image`,
      });
    }
    if (!parts.length) {
      w.push({ sev: 'medium', msg: '⚠ UDIF XML plist parsed but no partitions found — image may be malformed' });
    }
    return w;
  }

  _flagsLabel(flags) {
    const active = DmgRenderer.IMAGE_FLAGS.filter(f => flags & f.mask).map(f => f.label);
    return active.length ? active.join(', ') : `0x${flags.toString(16).padStart(8, '0')}`;
  }

  _checksumName(type) {
    switch (type) {
      case 0:  return 'none';
      case 1:  return 'CRC-32';
      case 2:  return 'MD5';
      case 3:  return 'SHA-1';
      case 0x2005: return 'SHA-256';
      default: return `type ${type}`;
    }
  }

  _contains(slice, needle) {
    outer: for (let i = 0; i + needle.length <= slice.length; i++) {
      for (let j = 0; j < needle.length; j++) if (slice[i + j] !== needle[j]) continue outer;
      return true;
    }
    return false;
  }

  _decodeBase64(str) {
    try {
      const bin = atob(str);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    } catch (e) { return null; }
  }

  _fmtBytes(n) {
    if (typeof fmtBytes === 'function') return fmtBytes(n);
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
    return (n / 1073741824).toFixed(1) + ' GB';
  }

  // Host whitelist check anchored to the URL's hostname (not a substring of
  // the full URL) so a domain like "evil-apple.com.attacker.example" is not
  // silently treated as Apple-owned. An unparsable URL is treated as NOT
  // Apple-owned — we'd rather over-report than hide a bad URL.
  _isAppleHost(u) {
    let host;
    try { host = new URL(u).hostname.toLowerCase(); }
    catch (e) { return false; }
    return host === 'apple.com'
      || host.endsWith('.apple.com');
  }
}
