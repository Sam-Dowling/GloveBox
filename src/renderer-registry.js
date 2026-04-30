'use strict';
// ════════════════════════════════════════════════════════════════════════════
// renderer-registry.js — Single source of truth for renderer auto-detection
//
// Every file format Loupe supports has exactly one entry here describing:
//
//   • which extensions it claims (strong hint)
//   • a magic-byte / container-structure predicate (strongest hint)
//   • an optional text-head sniff (for extensionless text formats)
//
// The registry then:
//
//   1. Exposes `static EXTS` + `static canHandle(ctx)` on each renderer
//      class by bootstrapping them at script load. Callers can ask
//      `PdfRenderer.canHandle(ctx)` or consult the class's `.EXTS`
//      without the renderer files having to duplicate detection logic.
//
//   2. Provides `RendererRegistry.detect(ctx)` which runs three passes
//      in order (magic → extension → text sniff) and returns the
//      rendering descriptor. This replaces the older, hand-maintained
//      if/else chain in `app-load.js` and closes the last gaps where a
//      renamed/stripped extension caused misclassification.
//
//   3. Owns the ZIP central-directory peek and OLE stream-name sniff
//      used to disambiguate container formats (DOCX vs MSIX vs JAR;
//      MSG vs MSI vs DOC). Results are cached on the context object
//      so each container is cracked at most once per file load.
//
// Contract for callers: construct a context with
// `RendererRegistry.makeContext(file, buffer)` and hand it to
// `detect()`. Do not pass raw bytes around — the context memoises
// the text heads and container peeks that most predicates want.
// ════════════════════════════════════════════════════════════════════════════

class RendererRegistry {

  // ── Registry entries ──────────────────────────────────────────────────────
  //
  // Ordering matters in two ways:
  //
  //   • Within the magic-pass the first match wins, so highly specific
  //     container sub-formats (MSIX / JAR / DOCX inside a ZIP; MSG / MSI
  //     inside OLE) MUST appear before their generic parent container.
  //
  //   • Within the extension-pass the first match wins. Overloaded
  //     extensions (.key, .pem, .manifest, .application) declare an
  //     `extDisambiguator` that returns false when the bytes say the
  //     file actually belongs to a different renderer.
  //
  // Each entry schema:
  //   id            : string           — dispatch key (used by app-load.js)
  //   className     : string           — global class name of the renderer
  //   exts          : string[]         — accepted extensions (no dot)
  //   magic?        : (ctx) => bool    — content-based predicate (strong)
  //   textSniff?    : (ctx) => bool    — text-head predicate (weaker)
  //   extDisambiguator? : (ctx) => bool — called when matched via ext; return
  //                                      false to skip this entry
  //   description   : string           — human label (for the codemap / tests)
  //
  // ──────────────────────────────────────────────────────────────────────────
  static ENTRIES = [

    // ── OLE sub-formats (must precede the generic OLE entry, which does not
    //    actually exist — all OLE paths are specific).
    {
      id: 'msg',
      className: 'MsgRenderer',
      exts: ['msg'],
      magic: (ctx) => {
        const names = ctx.oleStreams;
        if (!names) return false;
        for (const n of names) if (n.startsWith('__substg1.0_')) return true;
        return false;
      },
      description: 'Outlook Email Message (OLE)',
    },
    {
      id: 'msi',
      className: 'MsiRenderer',
      exts: ['msi'],
      magic: (ctx) => {
        const names = ctx.oleStreams;
        if (!names) return false;
        return names.has('!_stringpool') || names.has('!_stringdata');
      },
      description: 'Windows Installer (MSI)',
    },
    {
      id: 'doc',
      className: 'DocBinaryRenderer',
      exts: ['doc'],
      magic: (ctx) => ctx.oleStreams && ctx.oleStreams.has('worddocument'),
      description: 'Word 97-2003 Binary Document',
    },
    {
      id: 'xls',
      className: 'XlsxRenderer',
      exts: ['xlsx', 'xlsm', 'xls', 'ods'],
      magic: (ctx) => ctx.oleStreams && ctx.oleStreams.has('workbook'),
      description: 'Legacy Excel Binary Workbook (OLE path)',
    },
    {
      id: 'ppt',
      className: 'PptBinaryRenderer',
      exts: ['ppt'],
      magic: (ctx) => ctx.oleStreams &&
        (ctx.oleStreams.has('powerpoint document') ||
          ctx.oleStreams.has('current user')),
      description: 'Legacy PowerPoint Binary Presentation',
    },

    // ── ZIP sub-formats (must precede the generic ZIP entry).
    //
    //    MSIX and XPI/CRX must precede DOCX/XLSX/PPTX because a badly-
    //    crafted MSIX *could* theoretically also contain a word/ tree,
    //    and AppxManifest.xml is the authoritative marker.
    //    JAR must precede the generic ZIP, as .jar files that sit in a
    //    ZIP without the .jar extension should still be routed to the
    //    Java analyser.
    {
      id: 'msix',
      className: 'MsixRenderer',
      exts: ['msix', 'msixbundle', 'appx', 'appxbundle', 'appinstaller'],
      magic: (ctx) => {
        const entries = ctx.zipEntries;
        if (!entries) return false;
        for (const n of entries) {
          if (n === 'AppxManifest.xml' || n === 'AppxBundleManifest.xml') return true;
        }
        return false;
      },
      // .appinstaller is a standalone XML document (not ZIP). The renderer
      // handles both shapes internally, so the extension match is enough.
      description: 'MSIX / APPX / AppInstaller Package',
    },
    {
      id: 'browserext',
      className: 'BrowserExtRenderer',
      exts: ['crx', 'xpi'],
      magic: (ctx) => {
        const b = ctx.bytes;
        // Chrome / Edge CRX envelope: "Cr24" magic.
        if (b.length >= 4 && b[0] === 0x43 && b[1] === 0x72 && b[2] === 0x32 && b[3] === 0x34) return true;
        // Firefox XPI: ZIP with WebExtension manifest.json or legacy install.rdf.
        const entries = ctx.zipEntries;
        if (!entries) return false;
        let hasManifest = false, hasInstallRdf = false;
        for (const n of entries) {
          if (n === 'manifest.json') hasManifest = true;
          else if (n === 'install.rdf') hasInstallRdf = true;
        }
        if (hasInstallRdf) return true;
        // A bare root-level manifest.json is ambiguous in isolation
        // (many unrelated ZIPs ship one), but combined with a declared
        // .xpi / .crx extension it is the definitive modern WebExtension
        // shape — the legacy install.rdf marker disappeared with Firefox
        // 57 (2017), so keying solely on install.rdf would miss every
        // contemporary add-on. Random ZIPs that happen to carry a root
        // manifest.json still fall through to ZipRenderer because their
        // extension won't be xpi/crx.
        if (hasManifest && (ctx.ext === 'xpi' || ctx.ext === 'crx')) return true;
        return false;
      },
      description: 'Chrome/Edge CRX / Firefox XPI Extension',
    },
    {
      id: 'jar',
      className: 'JarRenderer',
      exts: ['jar', 'war', 'ear', 'class'],
      magic: (ctx) => {
        const b = ctx.bytes;
        // Raw Java .class file — delegate to JarRenderer.isJavaClass for
        // the full version-byte sanity check (CAFEBABE is shared with
        // Mach-O Fat binaries).
        if (b.length >= 10 && b[0] === 0xCA && b[1] === 0xFE && b[2] === 0xBA && b[3] === 0xBE) {
          if (typeof JarRenderer !== 'undefined' && JarRenderer.isJavaClass(b)) return true;
          // If it's CAFEBABE but not a class file, fall through (Mach-O Fat).
        }
        // JAR / WAR / EAR: ZIP with META-INF/MANIFEST.MF and at least one .class.
        const entries = ctx.zipEntries;
        if (!entries) return false;
        let hasManifest = false, hasClass = false;
        for (const n of entries) {
          if (n === 'META-INF/MANIFEST.MF') hasManifest = true;
          else if (n.endsWith('.class')) hasClass = true;
          if (hasManifest && hasClass) return true;
        }
        return false;
      },
      description: 'Java JAR / WAR / EAR / Class',
    },
    {
      id: 'docx',
      className: 'DocxParser', // pseudo — dispatched via the DOCX pipeline
      exts: ['docx', 'docm'],
      magic: (ctx) => {
        const entries = ctx.zipEntries;
        if (!entries) return false;
        for (const n of entries) if (n === 'word/document.xml') return true;
        return false;
      },
      description: 'Word OOXML Document',
    },
    {
      id: 'xlsx',
      className: 'XlsxRenderer',
      exts: ['xlsx', 'xlsm', 'ods'],
      magic: (ctx) => {
        const entries = ctx.zipEntries;
        if (!entries) return false;
        for (const n of entries) if (n === 'xl/workbook.xml') return true;
        return false;
      },
      description: 'Excel OOXML Workbook',
    },
    {
      id: 'pptx',
      className: 'PptxRenderer',
      exts: ['pptx', 'pptm'],
      magic: (ctx) => {
        const entries = ctx.zipEntries;
        if (!entries) return false;
        for (const n of entries) if (n === 'ppt/presentation.xml') return true;
        return false;
      },
      description: 'PowerPoint OOXML Presentation',
    },
    // OpenDocument family — ODF specifies that the `mimetype` member is
    // always first in the archive, stored uncompressed, so the mimetype
    // string sits at a well-known offset after the local file header.
    // We can sniff it without cracking the archive.
    {
      id: 'odt',
      className: 'OdtRenderer',
      exts: ['odt'],
      magic: (ctx) => ctx._odfMimeType === 'text',
      description: 'OpenDocument Text',
    },
    {
      id: 'odp',
      className: 'OdpRenderer',
      exts: ['odp'],
      magic: (ctx) => ctx._odfMimeType === 'presentation',
      description: 'OpenDocument Presentation',
    },
    {
      id: 'ods',
      className: 'XlsxRenderer', // SheetJS handles ODS
      exts: [], // routed by ext in xlsx entry; magic-only here
      magic: (ctx) => ctx._odfMimeType === 'spreadsheet',
      description: 'OpenDocument Spreadsheet',
    },

    // ── Non-container magic formats ───────────────────────────────────────
    {
      id: 'sqlite',
      className: 'SqliteRenderer',
      exts: ['sqlite', 'db'],
      magic: (ctx) => {
        const b = ctx.bytes;
        return b.length >= 16
          && b[0] === 0x53 && b[1] === 0x51 && b[2] === 0x4C && b[3] === 0x69
          && b[4] === 0x74 && b[5] === 0x65 && b[6] === 0x20;
      },
      description: 'SQLite Database',
    },
    {
      id: 'evtx',
      className: 'EvtxRenderer',
      exts: ['evtx'],
      magic: (ctx) => {
        const b = ctx.bytes;
        return b.length >= 8
          && b[0] === 0x45 && b[1] === 0x6C && b[2] === 0x66 && b[3] === 0x46
          && b[4] === 0x69 && b[5] === 0x6C && b[6] === 0x65 && b[7] === 0x00;
      },
      description: 'Windows Event Log',
    },
    {
      id: 'lnk',
      className: 'LnkRenderer',
      exts: ['lnk'],
      magic: (ctx) => {
        const b = ctx.bytes;
        return b.length >= 20
          && b[0] === 0x4C && b[1] === 0x00 && b[2] === 0x00 && b[3] === 0x00;
      },
      description: 'Windows Shell Link',
    },
    {
      id: 'pdf',
      className: 'PdfRenderer',
      exts: ['pdf'],
      magic: (ctx) => {
        const b = ctx.bytes;
        return b.length >= 4
          && b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46;
      },
      description: 'PDF Document',
    },
    {
      id: 'onenote',
      className: 'OneNoteRenderer',
      exts: ['one'],
      magic: (ctx) => {
        const b = ctx.bytes;
        return b.length >= 16
          && b[0] === 0xE4 && b[1] === 0x52 && b[2] === 0x5C && b[3] === 0x7B;
      },
      description: 'OneNote Document',
    },
    {
      id: 'iso',
      className: 'IsoRenderer',
      exts: ['iso', 'img'],
      magic: (ctx) => {
        const b = ctx.bytes;
        if (b.length <= 32768 + 5) return false;
        return b[32769] === 0x43 && b[32770] === 0x44 // C D
          && b[32771] === 0x30 && b[32772] === 0x30 // 0 0
          && b[32773] === 0x31;                      // 1
      },
      description: 'ISO 9660 Disk Image',
    },
    {
      // Apple Disk Image (UDIF) — 512-byte 'koly' trailer at end-of-file,
      // OR the encrypted-DMG envelopes ('encrcdsa' / 'cdsaencr' / 'AEA1')
      // at offset 0. DmgRenderer handles all three shapes internally so
      // any of them should route here before anything else claims them.
      id: 'dmg',
      className: 'DmgRenderer',
      exts: ['dmg'],
      magic: (ctx) => {
        const b = ctx.bytes;
        // Encrypted envelopes sit at offset 0.
        if (b.length >= 8) {
          if (b[0] === 0x41 && b[1] === 0x45 && b[2] === 0x41 && b[3] === 0x31) return true; // AEA1
          if (b[0] === 0x65 && b[1] === 0x6E && b[2] === 0x63 && b[3] === 0x72
            && b[4] === 0x63 && b[5] === 0x64 && b[6] === 0x73 && b[7] === 0x61) return true; // encrcdsa
          if (b[0] === 0x63 && b[1] === 0x64 && b[2] === 0x73 && b[3] === 0x61
            && b[4] === 0x65 && b[5] === 0x6E && b[6] === 0x63 && b[7] === 0x72) return true; // cdsaencr
        }
        // UDIF 'koly' magic at the 512-byte trailer.
        if (b.length < 512) return false;
        const off = b.length - 512;
        return b[off] === 0x6B && b[off + 1] === 0x6F
          && b[off + 2] === 0x6C && b[off + 3] === 0x79;
      },
      description: 'Apple Disk Image (UDIF / .dmg)',
    },
    {
      // macOS Installer Package — flat PKG is a xar archive ('xar!' at 0).
      // Must precede the generic ZIP entry even though xar isn't ZIP-prefixed,
      // to keep the magic pass ordered by specificity.
      id: 'pkg',
      className: 'PkgRenderer',
      exts: ['pkg', 'mpkg'],
      magic: (ctx) => {
        const b = ctx.bytes;
        return b.length >= 4
          && b[0] === 0x78 && b[1] === 0x61 && b[2] === 0x72 && b[3] === 0x21;
      },
      description: 'macOS Installer Package (flat PKG / xar)',
    },

    {
      id: 'scpt',
      className: 'OsascriptRenderer',
      exts: ['applescript', 'jxa', 'scpt', 'scptd'],
      // Compiled AppleScript (FasTX magic) OR text-scored AppleScript/JXA.
      magic: (ctx) => {
        const b = ctx.bytes;
        return b.length >= 4
          && b[0] === 0x46 && b[1] === 0x61 && b[2] === 0x73 && b[3] === 0x54;
      },
      textSniff: (ctx) => RendererRegistry._sniffAppleScript(ctx),
      description: 'AppleScript / JXA',
    },
    {
      id: 'plist',
      className: 'PlistRenderer',
      exts: ['plist'],
      magic: (ctx) => {
        const b = ctx.bytes;
        return b.length >= 8
          && b[0] === 0x62 && b[1] === 0x70 && b[2] === 0x6C && b[3] === 0x69
          && b[4] === 0x73 && b[5] === 0x74;
      },
      textSniff: (ctx) => {
        // XML plist — must have <plist> or <!DOCTYPE plist> somewhere in
        // the first 500 bytes (typically after the XML declaration).
        const h = ctx.head500;
        return /<plist[\s>]/i.test(h) || /<!DOCTYPE\s+plist/i.test(h);
      },
      description: 'Apple Property List',
    },
    {
      id: 'pgp',
      className: 'PgpRenderer',
      exts: ['pgp', 'gpg', 'asc', 'sig'],
      magic: (ctx) => {
        const b = ctx.bytes;
        if (b.length < 3) return false;
        // Binary OpenPGP packet header: Public-Key (0x99 / 0xC6), Secret-Key
        // (0x95 / 0xC5), Public-Subkey (0xB9 / 0xCE), Secret-Subkey (0x9D /
        // 0xC7). Require a plausible version byte {3,4,5,6} in the first 8
        // bytes to avoid false positives against other 0x9X-prefixed streams.
        if ([0x99, 0x95, 0xB9, 0x9D, 0xC6, 0xC5, 0xCE, 0xC7].includes(b[0])) {
          const scan = b.subarray(0, Math.min(8, b.length));
          for (const v of [3, 4, 5, 6]) {
            for (let i = 0; i < scan.length; i++) if (scan[i] === v) return true;
          }
        }
        return false;
      },
      textSniff: (ctx) => ctx.head.startsWith('-----BEGIN PGP'),
      // .key / .pem / .crt / .cer / .der are claimed by X509 too — defer
      // to X509 unless the bytes look like a PGP key.
      extDisambiguator: null,
      description: 'OpenPGP Key / Signature',
    },
    {
      id: 'x509',
      className: 'X509Renderer',
      exts: ['pem', 'der', 'crt', 'cer', 'p12', 'pfx', 'key'],
      magic: (ctx) => {
        const b = ctx.bytes;
        // DER: ASN.1 SEQUENCE with long-form length (0x30 0x82). The PGP
        // entry runs first in the magic pass; anything reaching this test
        // has already been ruled out as PGP.
        return b.length >= 4 && b[0] === 0x30 && b[1] === 0x82;
      },
      textSniff: (ctx) => {
        // PEM — but not a PGP armor block (which matches the same prefix).
        if (!ctx.head.startsWith('-----BEGIN ')) return false;
        return !ctx.head.startsWith('-----BEGIN PGP');
      },
      // For overloaded extensions (key/pem/crt/cer/der), only claim the
      // file if it doesn't look like PGP.
      extDisambiguator: (ctx) => !RendererRegistry._looksLikePgp(ctx.bytes),
      description: 'X.509 Certificate / PEM / DER / PKCS#12',
    },

    // ── Binary executables / object files ─────────────────────────────────
    {
      id: 'pe',
      className: 'PeRenderer',
      exts: ['exe', 'dll', 'sys', 'scr', 'cpl', 'ocx', 'drv', 'com', 'xll'],
      magic: (ctx) => ctx.bytes.length >= 2
        && ctx.bytes[0] === 0x4D && ctx.bytes[1] === 0x5A,
      description: 'Windows PE Executable',
    },
    {
      id: 'elf',
      className: 'ElfRenderer',
      exts: ['elf', 'so', 'o'],
      magic: (ctx) => ctx.bytes.length >= 4
        && ctx.bytes[0] === 0x7F && ctx.bytes[1] === 0x45
        && ctx.bytes[2] === 0x4C && ctx.bytes[3] === 0x46,
      description: 'Linux ELF Binary',
    },
    {
      id: 'macho',
      className: 'MachoRenderer',
      exts: ['dylib', 'bundle'],
      magic: (ctx) => {
        const b = ctx.bytes;
        if (b.length < 4) return false;
        // Thin Mach-O: 32-bit LE (CE FA ED FE), 64-bit LE (CF FA ED FE),
        // plus the BE variants.
        const m0 = b[0], m1 = b[1], m2 = b[2], m3 = b[3];
        if ((m0 === 0xCF && m1 === 0xFA && m2 === 0xED && m3 === 0xFE)
          || (m0 === 0xCE && m1 === 0xFA && m2 === 0xED && m3 === 0xFE)
          || (m0 === 0xFE && m1 === 0xED && m2 === 0xFA && (m3 === 0xCE || m3 === 0xCF))) {
          return true;
        }
        // Fat / Universal: CA FE BA BE — but only if not a Java class.
        if (m0 === 0xCA && m1 === 0xFE && m2 === 0xBA && m3 === 0xBE) {
          if (typeof JarRenderer !== 'undefined' && JarRenderer.isJavaClass(b)) return false;
          return true;
        }
        return false;
      },
      description: 'Mach-O Binary',
    },

    // ── Images ────────────────────────────────────────────────────────────
    {
      id: 'image',
      className: 'ImageRenderer',
      exts: ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'ico', 'tif', 'tiff', 'avif'],
      magic: (ctx) => RendererRegistry._sniffImage(ctx.bytes),
      description: 'Raster Image (PNG / JPEG / GIF / BMP / TIFF / ICO / WEBP / AVIF)',
    },

    // ── Archives ──────────────────────────────────────────────────────────
    //    Specific archive sub-formats (CAB / RAR / 7z) run BEFORE the
    //    generic `zip` entry so they are claimed by their dedicated
    //    renderers. The generic ZipRenderer still handles ZIP / OOXML /
    //    gzip / TAR and (via `_nonZip`) remains the safety-net fallback
    //    for any archive shape we cannot parse structurally.
    {
      id: 'cab',
      className: 'CabRenderer',
      exts: ['cab'],
      magic: (ctx) => {
        const b = ctx.bytes;
        return b.length >= 4
          && b[0] === 0x4D && b[1] === 0x53 && b[2] === 0x43 && b[3] === 0x46;
      },
      description: 'Microsoft Cabinet Archive (MSCF)',
    },
    {
      id: 'rar',
      className: 'RarRenderer',
      exts: ['rar'],
      magic: (ctx) => {
        const b = ctx.bytes;
        // RAR 1.5 – 4.x: "Rar!\x1A\x07\x00"
        // RAR 5.x:        "Rar!\x1A\x07\x01\x00"
        return b.length >= 7
          && b[0] === 0x52 && b[1] === 0x61 && b[2] === 0x72 && b[3] === 0x21
          && b[4] === 0x1A && b[5] === 0x07
          && (b[6] === 0x00 || b[6] === 0x01);
      },
      description: 'RAR Archive (v4 / v5, listing-only)',
    },
    {
      id: 'sevenz',
      className: 'SevenZRenderer',
      exts: ['7z'],
      magic: (ctx) => {
        const b = ctx.bytes;
        // 7z signature: 37 7A BC AF 27 1C
        return b.length >= 6
          && b[0] === 0x37 && b[1] === 0x7A && b[2] === 0xBC && b[3] === 0xAF
          && b[4] === 0x27 && b[5] === 0x1C;
      },
      description: '7-Zip Archive',
    },

    // ── npm package tarball / manifest / lockfile.
    //    Must precede the generic `zip` entry (which owns `.tgz`) so npm
    //    pack tarballs route to NpmRenderer instead of the plain archive
    //    viewer. Detection has three legs:
    //      • gzip-wrapped tarball whose first TAR entry name starts with
    //        "package/"  (the npm pack invariant)
    //      • bare `package.json` / `package-lock.json` / `npm-shrinkwrap.json`
    //        filename match
    //      • a JSON blob with the npm manifest shape  (name + one of
    //        scripts/dependencies/devDependencies/main/bin/version) — gated
    //        by the `extDisambiguator` so random `.json` files don't route
    //        here unless the bytes agree.
    {
      id: 'npm',
      className: 'NpmRenderer',
      exts: ['tgz', 'json'],
      magic: (ctx) => RendererRegistry._sniffNpmTarball(ctx),
      textSniff: (ctx) => RendererRegistry._sniffNpmManifest(ctx),
      extDisambiguator: (ctx) => {
        if (ctx.ext === 'tgz') return RendererRegistry._sniffNpmTarball(ctx);
        if (ctx.ext === 'json') return RendererRegistry._sniffNpmManifest(ctx)
          || /^(?:package|package-lock|npm-shrinkwrap)\.json$/i.test(ctx.file.name || '');
        return false;
      },
      description: 'npm Package (tarball / manifest / lockfile)',
    },

    // ── Generic ZIP / gzip / TAR fallback.  Any OOXML / ODF / MSIX /
    //    JAR / XPI / CRX sub-format has already claimed the file by the
    //    time we get here, and the dedicated CAB / RAR / 7z entries
    //    above claim those shapes. What's left is the plain container
    //    viewer used for vanilla ZIP / gzip / TAR archives.
    {
      id: 'zip',
      className: 'ZipRenderer',
      exts: ['zip', 'gz', 'gzip', 'tar', 'tgz'],
      magic: (ctx) => {
        const b = ctx.bytes;
        if (b.length < 4) return false;
        // ZIP / OOXML envelope
        if (b[0] === 0x50 && b[1] === 0x4B && b[2] === 0x03 && b[3] === 0x04) return true;
        // Gzip
        if (b[0] === 0x1F && b[1] === 0x8B) return true;
        // TAR (ustar magic at 257)
        if (b.length > 262
          && b[257] === 0x75 && b[258] === 0x73 && b[259] === 0x74
          && b[260] === 0x61 && b[261] === 0x72) return true;
        return false;
      },
      description: 'Archive (ZIP / OOXML-raw / gzip / TAR)',
    },

    // ── Text-head formats (magic-by-prefix) ───────────────────────────────
    {
      id: 'rtf',
      className: 'RtfRenderer',
      exts: ['rtf'],
      magic: (ctx) => ctx.head.startsWith('{\\rtf'),
      description: 'Rich Text Format',
    },
    {
      id: 'svg',
      className: 'SvgRenderer',
      exts: ['svg'],
      textSniff: (ctx) => {
        if (ctx.head.startsWith('<svg') || ctx.head.includes('<svg')) return true;
        if (ctx.head.startsWith('<?xml')) {
          return /<svg[\s>]/i.test(ctx.head200);
        }
        return false;
      },
      description: 'Scalable Vector Graphics',
    },
    {
      id: 'hta',
      className: 'HtaRenderer',
      exts: ['hta'],
      textSniff: (ctx) => ctx.head.startsWith('<HTA:') || ctx.head200.includes('<HTA:')
        || /<HTA:APPLICATION/i.test(ctx.head200),
      description: 'HTML Application',
    },
    {
      id: 'html',
      className: 'HtmlRenderer',
      exts: ['html', 'htm', 'mht', 'mhtml', 'xhtml'],
      textSniff: (ctx) => {
        const h = ctx.head;
        return h.startsWith('<!DOCTYPE') || h.startsWith('<html') || h.startsWith('<HTML');
      },
      description: 'HTML Document / MIME HTML',
    },
    {
      id: 'eml',
      className: 'EmlRenderer',
      exts: ['eml'],
      textSniff: (ctx) => {
        const h = ctx.head;
        return h.startsWith('From ') || h.startsWith('Received:') || h.startsWith('MIME-Version');
      },
      description: 'RFC 5322 / MIME Email',
    },
    {
      id: 'url',
      className: 'UrlShortcutRenderer',
      exts: ['url', 'webloc', 'website'],
      textSniff: (ctx) => ctx.head.startsWith('[InternetShortcut]'),
      description: 'Internet Shortcut',
    },
    {
      id: 'reg',
      className: 'RegRenderer',
      exts: ['reg'],
      textSniff: (ctx) => {
        if (ctx.head.startsWith('REGEDIT4') || ctx.head.startsWith('Windows Registry')) return true;
        // UTF-16LE variant: BOM FF FE then "Windows Registry…".
        const b = ctx.bytes;
        if (b.length >= 4 && b[0] === 0xFF && b[1] === 0xFE) {
          const u16 = new TextDecoder('utf-16le', { fatal: false })
            .decode(b.subarray(0, Math.min(80, b.length)));
          return u16.startsWith('Windows Registry');
        }
        return false;
      },
      description: 'Windows Registry File',
    },
    {
      id: 'inf',
      className: 'InfSctRenderer',
      exts: ['inf', 'sct'],
      textSniff: (ctx) => {
        const h = ctx.head200;
        // .inf: starts with [Version] (case-insensitive)
        if (/^\s*\[version\]/i.test(h)) return true;
        // .sct: XML scriptlet — <scriptlet>, <registration>, or <?XML version=…?>
        //       followed shortly by <script language=...>
        if (/<scriptlet\b/i.test(h) || /<registration\b/i.test(h)) return true;
        return false;
      },
      description: 'Setup Information / Windows Scriptlet',
    },
    {
      id: 'iqyslk',
      className: 'IqySlkRenderer',
      exts: ['iqy', 'slk'],
      textSniff: (ctx) => {
        const h = ctx.head;
        // IQY: line 1 is literal "WEB", line 2 is a version, line 3 is the URL.
        if (/^WEB\s*\r?\n/.test(h)) return true;
        // SLK: starts with "ID;" (SYLK record type)
        if (h.startsWith('ID;')) return true;
        return false;
      },
      description: 'Excel IQY / SYLK Data Query',
    },
    {
      // Windows Explorer Command — INI-format shell command file. Tiny
      // (typically ≤ 200 bytes), weaponised for T1187 forced authentication
      // when IconFile= points at a UNC path. We require the [Shell]
      // section header in the textSniff so we don't fight the generic
      // INI-as-plaintext fallback, and we keep the .scf extension match
      // unconditional because legitimate SCFs are vanishingly rare.
      id: 'scf',
      className: 'ScfRenderer',
      exts: ['scf'],
      textSniff: (ctx) => {
        const h = ctx.head200;
        return /\[Shell\]/i.test(h) && /IconFile\s*=/i.test(h);
      },
      description: 'Windows Explorer Command (.scf)',
    },
    {
      // .library-ms / .searchConnector-ms — both XML, both abused for
      // T1187 via UNC paths in <simpleLocation>/<url>. The two formats
      // share a renderer because the threat model and parser are
      // identical; the renderer auto-detects which root element is
      // present and labels accordingly.
      id: 'libraryms',
      className: 'LibraryMsRenderer',
      exts: ['library-ms', 'searchconnector-ms'],
      textSniff: (ctx) => {
        const h = ctx.head500;
        return /<libraryDescription\b/i.test(h)
            || /<searchConnectorDescription\b/i.test(h);
      },
      description: 'Windows Library / Search Connector',
    },
    {
      // Managed Object Format — WMI schema language compiled by mofcomp.exe.
      // Abused for ATT&CK T1546.003 (WMI Event Subscription persistence).
      // The textSniff anchors on `#pragma namespace` (canonical MOF
      // header) or `instance of` (instance-of-class declaration), both
      // of which are extremely rare outside genuine MOF files.
      id: 'mof',
      className: 'MofRenderer',
      exts: ['mof', 'mfl'],
      textSniff: (ctx) => {
        const h = ctx.head500;
        if (/#pragma\s+namespace/i.test(h)) return true;
        if (/\binstance\s+of\s+[A-Za-z_]/i.test(h)) return true;
        return false;
      },
      description: 'Managed Object Format (.mof) — WMI Schema',
    },
    {
      // XSLT stylesheet — abused for ATT&CK T1220 (SquiblyTwo signed
      // binary proxy execution via wmic.exe /format:<url> or msxsl.exe).
      // Two textSniff anchors: the canonical xsl:stylesheet root and
      // the older xsl:transform alias. Both bind to the W3C XSL ns.
      id: 'xslt',
      className: 'XsltRenderer',
      exts: ['xsl', 'xslt'],
      textSniff: (ctx) => {
        const h = ctx.head500;
        if (/<xsl:(stylesheet|transform)\b/i.test(h)) return true;
        if (/xmlns:xsl\s*=\s*["']http:\/\/www\.w3\.org\/1999\/XSL\/Transform/i.test(h)) return true;
        return false;
      },
      description: 'XSLT Stylesheet (.xsl / .xslt)',
    },
    {
      // WebAssembly binary module — magic-first dispatch on the canonical
      // 0x00 'a' 's' 'm' header. WASM is platform-agnostic; the .wasm
      // extension is also commonly present so we accept either signal.
      // Tiny WASM modules (< 8 bytes) fail the parser cleanly and surface
      // as a parse-error info IOC rather than a hard exception.
      id: 'wasm',
      className: 'WasmRenderer',
      exts: ['wasm'],
      magic: (ctx) => {
        const b = ctx.bytes;
        return b.length >= 4 && b[0] === 0x00 && b[1] === 0x61 && b[2] === 0x73 && b[3] === 0x6d;
      },
      description: 'WebAssembly Binary Module (.wasm)',
    },
    {
      // PCAP / PCAPNG — packet captures. Magic dispatch covers all four
      // libpcap variants (μs/ns × LE/BE) plus the PCAPNG SHB type. We
      // accept either signal (extension or magic) so .cap files (PCAP
      // body, no extension hint) and PCAPNG-renamed-to-.pcap also route
      // here. Both formats are handled by the single `pcap` dispatch
      // (PcapRenderer auto-detects PCAP vs PCAPNG from the first 4
      // bytes).
      id: 'pcap',
      className: 'PcapRenderer',
      exts: ['pcap', 'pcapng', 'cap'],
      magic: (ctx) => {
        const b = ctx.bytes;
        if (b.length < 4) return false;
        // PCAPNG SHB block-type 0x0a0d0d0a (always BE on the wire).
        if (b[0] === 0x0a && b[1] === 0x0d && b[2] === 0x0d && b[3] === 0x0a) return true;
        // libpcap classic — four magic variants:
        if (b[0] === 0xa1 && b[1] === 0xb2 && b[2] === 0xc3 && b[3] === 0xd4) return true; // μs BE
        if (b[0] === 0xd4 && b[1] === 0xc3 && b[2] === 0xb2 && b[3] === 0xa1) return true; // μs LE
        if (b[0] === 0xa1 && b[1] === 0xb2 && b[2] === 0x3c && b[3] === 0x4d) return true; // ns BE
        if (b[0] === 0x4d && b[1] === 0x3c && b[2] === 0xb2 && b[3] === 0xa1) return true; // ns LE
        return false;
      },
      description: 'Packet capture (.pcap / .pcapng / .cap)',
    },
    {
      id: 'wsf',
      className: 'WsfRenderer',
      exts: ['wsf', 'wsc', 'wsh'],
      textSniff: (ctx) => {
        const h = ctx.head200;
        // WSF root elements:  <job>, <package>, <?job ...?>
        // WSC (scriptlet):    <component>, <scriptlet> (shared with .sct)
        // WSH (settings ini): [ScriptFile]  — pure INI, low risk
        if (/<job\b/i.test(h) || /<package\b/i.test(h)) return true;
        if (/<\?job\b/i.test(h)) return true;
        if (/<component\b/i.test(h) && /<script\b/i.test(h)) return true;
        if (/^\s*\[ScriptFile\]/i.test(h)) return true;
        return false;
      },
      description: 'Windows Script File',
    },
    {
      id: 'clickonce',
      className: 'ClickOnceRenderer',
      exts: ['application', 'manifest'],
      textSniff: (ctx) => RendererRegistry._sniffClickOnce(ctx),
      extDisambiguator: (ctx) => RendererRegistry._sniffClickOnce(ctx),
      description: 'ClickOnce Deployment / Application Manifest',
    },
    {
      id: 'csv',
      className: 'CsvRenderer',
      exts: ['csv', 'tsv'],
      // CSV / TSV have no content signature — pure extension match. The
      // renderer refuses unconvincing inputs so misroutes degrade
      // gracefully into the plaintext fallback.
      description: 'CSV / TSV Tabular Data',
    },

    // ── JSON (array-shaped) + NDJSON — tabular viewer on top of GridViewer.
    //    Must run AFTER `npm` so package.json / package-lock.json still
    //    route to NpmRenderer (npm's extDisambiguator insists on the npm
    //    shape, so non-npm JSON falls through to us).
    //
    //    `extDisambiguator`: claim `.json` only if the bytes parse and the
    //    root is an array (or the blob looks like NDJSON). Object-root and
    //    scalar-root JSON fall through to PlainTextRenderer which still
    //    renders them with JSON syntax highlighting. The extDisambiguator
    //    is deliberately liberal for `.ndjson` / `.jsonl` — those extensions
    //    are unambiguous on their own.
    {
      id: 'json',
      className: 'JsonRenderer',
      exts: ['json', 'ndjson', 'jsonl'],
      extDisambiguator: (ctx) => {
        if (ctx.ext === 'ndjson' || ctx.ext === 'jsonl') return true;
        return RendererRegistry._sniffJsonArrayOrNdjson(ctx);
      },
      // No magic / textSniff — we only claim via extension. Extensionless
      // JSON still falls through to PlainTextRenderer (which highlights it).
      description: 'JSON / NDJSON Tabular Data',
    },

    // ── Catch-all — always last. `detect()` falls through to here for any
    //    file that no earlier entry claimed.
    {
      id: 'plaintext',
      className: 'PlainTextRenderer',
      exts: [], // unreachable via ext — it's the fallback
      description: 'Plain Text / Hex Dump Fallback',
    },
  ];

  // ── Context construction ──────────────────────────────────────────────────
  //
  // Builds a single object that detection predicates read from. Text
  // heads and container peeks are precomputed / memoised here so the
  // dozens of predicates below touch the bytes at most once each.
  // Container peeks (OLE streams, ZIP entries, ODF mimetype) are
  // defined as lazy getters — a plain-text file never pays the
  // archive-parse cost.
  static makeContext(file, buffer) {
    const bytes = new Uint8Array(buffer);
    const ext = (file.name.split('.').pop() || '').toLowerCase();
    const sliceAscii = (n) => {
      if (bytes.length === 0) return '';
      const end = Math.min(n, bytes.length);
      let s = '';
      for (let i = 0; i < end; i++) s += String.fromCharCode(bytes[i]);
      return s;
    };
    const head = sliceAscii(20);
    const head200 = sliceAscii(200);
    const head500 = sliceAscii(500);
    const head4k = sliceAscii(4096);

    const ctx = { file, buffer, bytes, ext, head, head200, head500, head4k };

    // Lazy OLE stream enumeration — only runs when a predicate asks.
    let _ole = undefined;
    Object.defineProperty(ctx, 'oleStreams', {
      get() {
        if (_ole !== undefined) return _ole;
        if (!(bytes.length >= 4
          && bytes[0] === 0xD0 && bytes[1] === 0xCF
          && bytes[2] === 0x11 && bytes[3] === 0xE0)) {
          return (_ole = null);
        }
        if (typeof OleCfbParser === 'undefined') return (_ole = null);
        try {
          const parser = new OleCfbParser(buffer);
          parser.parseMetadataOnly();
          return (_ole = new Set(parser.streamMeta.keys()));
        } catch (e) { return (_ole = null); }
      },
    });

    // Lazy ZIP central-directory peek — returns Set of entry names.
    let _zip = undefined;
    Object.defineProperty(ctx, 'zipEntries', {
      get() {
        if (_zip !== undefined) return _zip;
        // Require ZIP local-header magic "PK\x03\x04" to even try.
        if (!(bytes.length >= 4
          && bytes[0] === 0x50 && bytes[1] === 0x4B
          && bytes[2] === 0x03 && bytes[3] === 0x04)) {
          return (_zip = null);
        }
        try { return (_zip = RendererRegistry._scanZipCentralDir(bytes)); }
        catch (e) { return (_zip = null); }
      },
    });

    // Lazy ODF mimetype sniff — ODF stores `mimetype` as the first member,
    // uncompressed, so the mimetype string sits at offset 38 (30-byte
    // local file header + 8-byte "mimetype" filename). We only peek if
    // the file is a ZIP and contains a `mimetype` entry.
    let _odf = undefined;
    Object.defineProperty(ctx, '_odfMimeType', {
      get() {
        if (_odf !== undefined) return _odf;
        const entries = ctx.zipEntries;
        if (!entries || !entries.has('mimetype')) return (_odf = null);
        // Search for the ODF mimetype string in the first ~200 bytes.
        const head = sliceAscii(256);
        if (head.includes('application/vnd.oasis.opendocument.text')) return (_odf = 'text');
        if (head.includes('application/vnd.oasis.opendocument.presentation')) return (_odf = 'presentation');
        if (head.includes('application/vnd.oasis.opendocument.spreadsheet')) return (_odf = 'spreadsheet');
        if (head.includes('application/vnd.oasis.opendocument.graphics')) return (_odf = 'graphics');
        return (_odf = null);
      },
    });

    return ctx;
  }

  // ── Query API ─────────────────────────────────────────────────────────────

  /**
   * Return whether a given renderer id can handle the given context.
   * @param {string} id  The renderer id from the ENTRIES table.
   * @param {object} ctx Context built by makeContext().
   * @returns {'magic'|'ext'|'sniff'|null}
   */
  static canHandle(id, ctx) {
    const e = this.ENTRIES.find(r => r.id === id);
    if (!e) return null;
    if (e.magic && e.magic(ctx)) return 'magic';
    if (ctx.ext && e.exts.includes(ctx.ext)) {
      if (e.extDisambiguator && !e.extDisambiguator(ctx)) return null;
      return 'ext';
    }
    if (e.textSniff && e.textSniff(ctx)) return 'sniff';
    return null;
  }

  /**
   * Run the three detection passes and return the first winner.
   *   Pass 1: magic (content-based, strong)
   *   Pass 2: extension
   *   Pass 3: text sniff (weakest)
   * Falls back to the plaintext renderer if nothing matches.
   * @returns {{ id, entry, via }}
   */
  static detect(ctx) {
    // Pass 1 — magic / content.
    for (const e of this.ENTRIES) {
      if (e.magic && e.magic(ctx)) return { id: e.id, entry: e, via: 'magic' };
    }
    // Pass 2 — extension.
    for (const e of this.ENTRIES) {
      if (!ctx.ext || !e.exts.length || !e.exts.includes(ctx.ext)) continue;
      if (e.extDisambiguator && !e.extDisambiguator(ctx)) continue;
      return { id: e.id, entry: e, via: 'ext' };
    }
    // Pass 3 — text sniff.
    for (const e of this.ENTRIES) {
      if (e.textSniff && e.textSniff(ctx)) return { id: e.id, entry: e, via: 'sniff' };
    }
    // Fallback — plaintext renderer.
    const pt = this.ENTRIES.find(r => r.id === 'plaintext');
    return { id: 'plaintext', entry: pt, via: 'fallback' };
  }

  // ── Shared helpers ────────────────────────────────────────────────────────

  /**
   * Heuristic: does this buffer look like OpenPGP data? Used for the
   * overloaded .key / .pem / .crt / .cer / .der extensions to decide
   * between X509Renderer and PgpRenderer.
   */
  static _looksLikePgp(bytes) {
    if (!bytes || bytes.length < 4) return false;
    // ASCII-armored
    const head = String.fromCharCode(...bytes.subarray(0, Math.min(64, bytes.length)));
    if (head.includes('-----BEGIN PGP ')) return true;
    // Binary OpenPGP packet header (old & new format).
    const first = bytes[0];
    return [0x99, 0x95, 0xB9, 0x9D, 0xC6, 0xC5, 0xCE, 0xC7].includes(first);
  }

  /**
   * Image magic-byte sniff. Covers the full set of extensions the
   * ImageRenderer accepts — PNG / JPEG / GIF / BMP / TIFF (both endians) /
   * ICO / RIFF-WEBP / ISO-BMFF-AVIF.
   */
  static _sniffImage(b) {
    if (b.length < 4) return false;
    // PNG
    if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4E && b[3] === 0x47) return true;
    // JPEG
    if (b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF) return true;
    // GIF
    if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46) return true;
    // BMP
    if (b[0] === 0x42 && b[1] === 0x4D) return true;
    // TIFF little-endian (II*\0)
    if (b[0] === 0x49 && b[1] === 0x49 && b[2] === 0x2A && b[3] === 0x00) return true;
    // TIFF big-endian (MM\0*)
    if (b[0] === 0x4D && b[1] === 0x4D && b[2] === 0x00 && b[3] === 0x2A) return true;
    // ICO: 00 00 01 00 (type 1 = icon)
    if (b[0] === 0x00 && b[1] === 0x00 && b[2] === 0x01 && b[3] === 0x00 && b.length >= 22) return true;
    // CUR: 00 00 02 00 (type 2 = cursor) — same container as ICO
    if (b[0] === 0x00 && b[1] === 0x00 && b[2] === 0x02 && b[3] === 0x00 && b.length >= 22) return true;
    // RIFF WEBP: "RIFF" … "WEBP"
    if (b.length >= 12
      && b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46
      && b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return true;
    // AVIF / HEIF — ISO BMFF `ftyp` box at offset 4.
    //   bytes 4..7 = "ftyp"
    //   bytes 8..11 = brand: "avif"|"avis"|"heic"|"heix"|"mif1"|…
    if (b.length >= 16
      && b[4] === 0x66 && b[5] === 0x74 && b[6] === 0x79 && b[7] === 0x70) {
      const brand = String.fromCharCode(b[8], b[9], b[10], b[11]);
      if (brand === 'avif' || brand === 'avis' || brand === 'heic'
        || brand === 'heix' || brand === 'mif1' || brand === 'msf1'
        || brand === 'heim' || brand === 'heis') return true;
    }
    return false;
  }

  /**
   * AppleScript / JXA text heuristic. Kept here because several renderers
   * want the same decision. Score-based so a lone "tell me" in prose
   * doesn't get hijacked.
   */
  static _sniffAppleScript(ctx) {
    const head4k = ctx.head4k;
    if (!head4k) return false;
    const nonPrintable = (head4k.match(/[\x00-\x08\x0E-\x1F]/g) || []).length;
    if (nonPrintable / Math.max(head4k.length, 1) >= 0.01) return false;
    let score = 0;
    if (/\btell\s+application\s+"/i.test(head4k)) score += 3;
    if (/\bdo\s+shell\s+script\s+"/i.test(head4k)) score += 3;
    if (/\bend\s+tell\b/i.test(head4k)) score += 2;
    if (/\bon\s+run\b|\bon\s+open\b|\bon\s+idle\b/i.test(head4k)) score += 2;
    if (/\bset\s+\w[\w ]*\s+to\s+/i.test(head4k)) score += 1;
    if (/\bwith\s+administrator\s+privileges\b/i.test(head4k)) score += 2;
    if (/\bthe\s+clipboard\b/i.test(head4k)) score += 1;
    if (/\bproperty\s+\w+\s*:/i.test(head4k)) score += 1;
    if (/\bActiveXObject\b/.test(head4k)) score -= 3; // JScript, not JXA
    if (/^\s*#!/m.test(head4k) && !/osascript/i.test(head4k)) score -= 2;
    return score >= 5;
  }

  /**
   * ClickOnce deployment / application manifest sniff. The `.manifest`
   * extension is overloaded — SxS, vcpkg, Visual Studio project, and
   * ClickOnce manifests all share `<assembly>`. We need BOTH the assembly
   * root AND a ClickOnce-specific signal (asm.v1/v2 URN, <deployment>,
   * <entryPoint>, or <trustInfo>) before claiming the file.
   */
  static _sniffClickOnce(ctx) {
    const preview = ctx.head4k;
    const hasAssemblyRoot = /<\s*(?:\w+:)?assembly\b/i.test(preview);
    if (!hasAssemblyRoot) return false;
    return /urn:schemas-microsoft-com:asm\.v[12]/i.test(preview)
      || /<\s*(?:\w+:)?deployment\b/i.test(preview)
      || /<\s*(?:\w+:)?entryPoint\b/i.test(preview)
      || /<\s*(?:\w+:)?trustInfo\b/i.test(preview);
  }

  /**
   * npm package tarball sniff — returns true if the bytes are a gzip
   * stream whose first TAR member name begins with "package/". We
   * inflate only the first ~1 KB of the gzip, enough to read the
   * 100-byte TAR header at offset 0. `Decompressor` is available at
   * runtime (loaded before the registry in build order); if it isn't
   * we conservatively say "not npm" and let the generic ZipRenderer
   * handle the tarball.
   */
  static _sniffNpmTarball(ctx) {
    const b = ctx.bytes;
    if (b.length < 10) return false;
    // gzip magic
    if (!(b[0] === 0x1F && b[1] === 0x8B)) return false;
    if (typeof Decompressor === 'undefined'
      || typeof Decompressor.inflateSync !== 'function') return false;
    if (ctx._npmTarPeek !== undefined) return ctx._npmTarPeek;
    try {
      // We only need the first TAR header (512 bytes). For tarballs bigger
      // than ~1 MB, cap the gzip slice we feed pako to avoid paying the
      // full inflate cost during detection. For smaller inputs we pass the
      // whole buffer; pako handles it synchronously in microseconds.
      const slice = (b.length > 1024 * 1024) ? b.subarray(0, 256 * 1024) : b;
      const out = Decompressor.inflateSync(slice, 'gzip');
      if (!out || out.length < 100) return (ctx._npmTarPeek = false);
      // First TAR header name lives at bytes 0..99, NUL-terminated.
      let name = '';
      for (let i = 0; i < 100 && out[i]; i++) name += String.fromCharCode(out[i]);
      return (ctx._npmTarPeek = /^package\//.test(name));
    } catch (_) {
      return (ctx._npmTarPeek = false);
    }
  }

  /**
   * npm package.json / lockfile manifest sniff — parses the head as JSON
   * and checks for the minimal npm shape:
   *   • `name` (string), AND
   *   • at least one of: version / scripts / dependencies / devDependencies
   *     / peerDependencies / optionalDependencies / main / bin / exports
   * OR the lockfile shape: `lockfileVersion` numeric at the root.
   * Returns false on anything that isn't valid JSON or doesn't match.
   */
  static _sniffNpmManifest(ctx) {
    const b = ctx.bytes;
    if (b.length < 2 || b.length > 32 * 1024 * 1024) return false;
    // Quick gate — must start with `{` (after optional UTF-8 BOM / whitespace).
    let i = 0;
    if (b[0] === 0xEF && b[1] === 0xBB && b[2] === 0xBF) i = 3;
    while (i < b.length && (b[i] === 0x20 || b[i] === 0x09 || b[i] === 0x0A || b[i] === 0x0D)) i++;
    if (i >= b.length || b[i] !== 0x7B) return false;
    let text;
    try {
      text = new TextDecoder('utf-8', { fatal: false }).decode(b);
    } catch (_) { return false; }
    let obj;
    try { obj = JSON.parse(text); } catch (_) { return false; }
    if (!obj || typeof obj !== 'object') return false;
    // Lockfile shape.
    if (typeof obj.lockfileVersion === 'number') return true;
    // Manifest shape.
    if (typeof obj.name !== 'string' || !obj.name) return false;
    const shapeKeys = ['version', 'scripts', 'dependencies', 'devDependencies',
      'peerDependencies', 'optionalDependencies', 'bundledDependencies',
      'main', 'bin', 'exports', 'module', 'browser', 'engines'];
    for (const k of shapeKeys) if (k in obj) return true;
    return false;
  }

  /**
   * JSON-array / NDJSON sniff — decides whether JsonRenderer should claim
   * a `.json` file. True if:
   *   • the bytes parse as JSON and the root is an Array, OR
   *   • the head of the blob looks like NDJSON (every non-empty line is a
   *     standalone JSON value starting with `{` or `[`).
   * Anything else (object-root / scalar-root / unparseable) falls through
   * to PlainTextRenderer which still syntax-highlights it.
   *
   * Parse cost-cap: we refuse to parse anything over 32 MiB during
   * detection — a pathological 100 MB JSON blob would spike memory just
   * to decide how to route it. Over-cap files fall through to plaintext.
   */
  static _sniffJsonArrayOrNdjson(ctx) {
    const b = ctx.bytes;
    if (b.length < 2) return false;
    if (b.length > 32 * 1024 * 1024) return false;

    // Skip BOM + leading whitespace to find the first meaningful byte.
    let i = 0;
    if (b[0] === 0xEF && b[1] === 0xBB && b[2] === 0xBF) i = 3;
    while (i < b.length && (b[i] === 0x20 || b[i] === 0x09 || b[i] === 0x0A || b[i] === 0x0D)) i++;
    if (i >= b.length) return false;
    const first = b[i];

    // Array root — `[` is the cheap, definitive signal. Parse just to
    // confirm the JSON is well-formed.
    if (first === 0x5B /* '[' */) {
      try {
        const text = new TextDecoder('utf-8', { fatal: false }).decode(b);
        const v = JSON.parse(text);
        return Array.isArray(v);
      } catch (_) { return false; }
    }

    // Object root — only claim if the blob looks like NDJSON (every
    // non-empty head line is a standalone JSON value on its own line).
    if (first === 0x7B /* '{' */) {
      const headLen = Math.min(16384, b.length);
      let head = '';
      try { head = new TextDecoder('utf-8', { fatal: false }).decode(b.subarray(0, headLen)); }
      catch (_) { return false; }
      const lines = head.split('\n').map(l => l.trim()).filter(Boolean);
      if (lines.length < 2) return false;
      const checkN = Math.min(8, lines.length);
      for (let k = 0; k < checkN; k++) {
        const c = lines[k][0];
        if (c !== '{' && c !== '[') return false;
        try { JSON.parse(lines[k]); } catch (_) { return false; }
      }
      return true;
    }
    return false;
  }

  /**
   * Script-language sniff for files Loupe routes to PlainTextRenderer.
   *
   * Returns one of `'ps1' | 'bash' | 'bat' | 'vbs' | 'js' | 'py' | 'perl'`
   * when the head of the buffer matches *two independent* indicators for
   * that language (one indicator is too noisy — `function` appears in a
   * lot of non-JS docs, `param(` appears in C-family code). Returns
   * `null` when the buffer is binary, empty, or doesn't look like one of
   * the supported script languages — caller treats `null` as "leave
   * `formatTag` as plaintext".
   *
   * This is a Loupe extension layered ON TOP of the renderer dispatch:
   * it does not change which renderer paints the file (PlainText), only
   * the `formatTag` consumed by `YaraEngine`'s `is_*` predicates and
   * `meta: applies_to` gates. See `src/yara-engine.js` for the contract.
   *
   * Conservative on purpose — false-tagging a benign Markdown as `bash`
   * would resurrect the false-positive class the audit flagged. When
   * scores tie or both binary indicators trip, return `null` and let
   * the rules see plain `plaintext`.
   *
   * @param {object} ctx  RendererRegistry.makeContext output
   * @returns {string|null}
   */
  static _sniffScriptKind(ctx) {
    const head = ctx && ctx.head4k;
    if (!head || head.length < 8) return null;

    // Bail on binary content — > 1 % control bytes in the head means
    // we're not looking at source.
    const nonPrintable = (head.match(/[\x00-\x08\x0E-\x1F]/g) || []).length;
    if (nonPrintable / head.length >= 0.01) return null;

    // Trim a UTF-8 BOM if present so shebang detection works.
    const h = head.charCodeAt(0) === 0xFEFF ? head.slice(1) : head;
    const headLower = h.toLowerCase();

    // ── Shebang fast-path ───────────────────────────────────────────────
    // Shebangs are a single, unambiguous signal — one indicator suffices.
    const sb = h.match(/^#!\s*\S*\/(?:env\s+)?(\S+)/);
    if (sb) {
      const cmd = sb[1].toLowerCase();
      if (/^(?:pwsh|powershell)$/.test(cmd)) return 'ps1';
      if (/^(?:sh|bash|zsh|dash|ksh|ash)$/.test(cmd)) return 'bash';
      if (/^python\d?$/.test(cmd)) return 'py';
      if (cmd === 'node' || cmd === 'nodejs' || cmd === 'deno') return 'js';
      if (cmd === 'perl') return 'perl';
      if (cmd === 'osascript') return null; // routed to scpt by registry
    }

    // ── Score-based detection (need ≥2 indicators per language) ─────────
    // Each language has a cheap regex bag; the highest-scoring language
    // with a score ≥ 2 wins. Ties resolve to `null` (ambiguous → don't
    // tag).
    const scores = { ps1: 0, bash: 0, bat: 0, vbs: 0, js: 0, py: 0, perl: 0 };

    // PowerShell — strong markers: `<#`/`#>` block comments,
    // `[CmdletBinding()]`, `param(` paired with `[Parameter`, well-known
    // verb-noun cmdlets, `Set-StrictMode`.
    if (/<#[\s\S]*?#>/.test(h)) scores.ps1 += 2;
    if (/\bSet-StrictMode\b/i.test(h)) scores.ps1 += 2;
    if (/\[CmdletBinding\s*\(/i.test(h)) scores.ps1 += 2;
    if (/\bparam\s*\(\s*\[/i.test(h)) scores.ps1 += 1;
    if (/\b(?:Get|Set|New|Remove|Invoke|Start|Stop|Test|Add|Out|Write|Read|Import|Export|Select|Where|ForEach)-[A-Z]\w+/.test(h)) scores.ps1 += 1;
    if (/\$(?:PSScriptRoot|PSCommandPath|MyInvocation|ErrorActionPreference|VerbosePreference)\b/i.test(h)) scores.ps1 += 2;

    // Bash / POSIX shell — `set -e`/`set -u`, `function name() {`,
    // `$1`/`$@` parameters, common builtins, `[[ … ]]`.
    if (/^\s*set\s+-[eu]+\b/m.test(h)) scores.bash += 2;
    if (/\bfunction\s+\w+\s*\(\s*\)\s*\{/.test(h)) scores.bash += 2;
    if (/\b(?:if|while|for)\s+\[\[?[^\n]+\]\]?\s*;\s*then\b/.test(h)) scores.bash += 2;
    if (/\$\{?(?:[1-9]|@|\*|#|\?)\}?/.test(h)) scores.bash += 1;
    if (/\b(?:echo|read|export|local|readonly|declare|trap|source)\b\s/.test(h)) scores.bash += 1;
    if (/\$\([^)]+\)|`[^`]+`/.test(h)) scores.bash += 1;

    // Windows BAT/CMD — `@echo off`, `goto :label`, `%~dp0`,
    // `setlocal enabledelayedexpansion`, `%var%`, `:label` lines.
    if (/^\s*@echo\s+(?:off|on)\b/im.test(h)) scores.bat += 2;
    if (/\bsetlocal\b/i.test(h)) scores.bat += 2;
    if (/%~[dpnxfsa01-9]+\d*/i.test(h)) scores.bat += 2;
    if (/\bgoto\s+:?\w+/i.test(h)) scores.bat += 1;
    if (/^\s*:\w+\s*$/m.test(h)) scores.bat += 1;
    if (/%\w+%/.test(h) && /\b(?:set|if|for|call)\b/i.test(h)) scores.bat += 1;

    // VBScript — `Option Explicit`, `Set obj = CreateObject(`,
    // `Sub … End Sub`, `Function … End Function`, `Wscript.`/`MsgBox`.
    if (/^\s*Option\s+Explicit\b/im.test(h)) scores.vbs += 2;
    if (/\bSet\s+\w+\s*=\s*CreateObject\s*\(/i.test(h)) scores.vbs += 2;
    if (/\bDim\s+\w+(?:\s*,\s*\w+)*\s*$/im.test(h)) scores.vbs += 1;
    if (/\b(?:Sub|Function)\s+\w+[\s\S]{0,400}?\bEnd\s+(?:Sub|Function)\b/i.test(h)) scores.vbs += 2;
    if (/\b(?:WScript|Wscript)\.(?:Echo|Quit|CreateObject|Sleep|Shell|Arguments)\b/.test(h)) scores.vbs += 2;
    if (/\bOn\s+Error\s+Resume\s+Next\b/i.test(h)) scores.vbs += 2;

    // JavaScript / Node — `require(`, `module.exports`, `import … from`,
    // arrow `=>` paired with `const/let`, `=>`/`async function`, JSDoc.
    if (/\brequire\s*\(\s*['"]/.test(h)) scores.js += 2;
    if (/\bmodule\.exports\b|\bexports\.\w+\s*=/.test(h)) scores.js += 2;
    if (/\bimport\s+[^\n;]+\s+from\s+['"]/.test(h)) scores.js += 2;
    if (/\bexport\s+(?:default\s+)?(?:function|class|const|let|var)\b/.test(h)) scores.js += 2;
    if (/\b(?:const|let)\s+\w+\s*=\s*(?:\([^)]*\)|\w+)\s*=>/.test(h)) scores.js += 1;
    if (/\basync\s+function\s+\w+/.test(h)) scores.js += 1;

    // Python — `def name(`, `import x`/`from x import`, `if __name__`,
    // common `print(...)` (3.x) with a `def`, decorator `@\w+`.
    if (/^\s*def\s+\w+\s*\(/m.test(h)) scores.py += 2;
    if (/^\s*(?:from\s+\w[\w.]*\s+import\b|import\s+\w[\w.,\s]*$)/m.test(h)) scores.py += 2;
    if (/\bif\s+__name__\s*==\s*['"]__main__['"]\s*:/.test(h)) scores.py += 2;
    if (/^\s*@\w[\w.]*(?:\s*\([^)]*\))?\s*$/m.test(h)) scores.py += 1;
    if (/^\s*class\s+\w+\s*(?:\([^)]*\))?\s*:/m.test(h)) scores.py += 1;

    // Perl — `use strict`, `my $`/`our @`, sigil-heavy variables,
    // `package Foo;`, `sub name {`.
    if (/\buse\s+(?:strict|warnings|utf8)\b/.test(h)) scores.perl += 2;
    if (/\b(?:my|our|local)\s+[\$@%]\w+/.test(h)) scores.perl += 2;
    if (/^\s*package\s+\w[\w:]*\s*;/m.test(h)) scores.perl += 2;
    if (/\bsub\s+\w+\s*\{/.test(h)) scores.perl += 1;

    // Penalty: `<html`, `<svg`, `<?xml`, JSON-style heads — these are
    // markup and shouldn't be tagged as scripts even if some incidental
    // signal hits.
    if (/^\s*<\?xml\b/i.test(headLower) || /^\s*<!doctype\s/i.test(headLower)
        || /^\s*<(?:html|svg)\b/i.test(headLower)) {
      // Strong negative — wipe all script scores. Markup is markup.
      for (const k of Object.keys(scores)) scores[k] = 0;
    }

    // Pick the winner — must score ≥2 and beat the runner-up by ≥1
    // (otherwise it's ambiguous; safer to leave as plaintext).
    let bestKind = null, bestScore = 0, runnerUp = 0;
    for (const k of Object.keys(scores)) {
      if (scores[k] > bestScore) { runnerUp = bestScore; bestScore = scores[k]; bestKind = k; }
      else if (scores[k] > runnerUp) { runnerUp = scores[k]; }
    }
    if (bestScore < 2) return null;
    if (bestScore - runnerUp < 1) return null;
    return bestKind;
  }

  /**
   * Parse the ZIP End-of-Central-Directory + central directory to
   * extract the list of entry filenames. Returns a Set<string> or
   * null on malformed archives. Does NOT decompress anything.
   */
  static _scanZipCentralDir(bytes) {
    // EOCD record: PK\x05\x06. Appears in the last 22..65557 bytes of the
    // archive (22 for a zero-length comment, plus up to 65535 comment bytes).
    const maxScan = Math.min(bytes.length, 22 + 65535);
    let eocdOff = -1;
    const scanStart = Math.max(0, bytes.length - maxScan);
    for (let i = bytes.length - 22; i >= scanStart; i--) {
      if (bytes[i] === 0x50 && bytes[i + 1] === 0x4B
        && bytes[i + 2] === 0x05 && bytes[i + 3] === 0x06) {
        eocdOff = i;
        break;
      }
    }
    if (eocdOff < 0) return null;

    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    // EOCD layout:
    //   off+10: total number of entries in central directory
    //   off+12: size of central directory (bytes)
    //   off+16: offset of central directory from start of archive
    const totalEntries = dv.getUint16(eocdOff + 10, true);
    const cdOff = dv.getUint32(eocdOff + 16, true);

    // Cap how many entries we enumerate — even a pathological zip bomb
    // declaring millions of entries can't blow the budget.
    const MAX_ENTRIES = 4096;
    const cap = Math.min(totalEntries, MAX_ENTRIES);
    const names = new Set();
    let p = cdOff;
    const dec = new TextDecoder('utf-8', { fatal: false });
    for (let i = 0; i < cap && p + 46 <= bytes.length; i++) {
      // Central directory entry signature: PK\x01\x02
      if (dv.getUint32(p, true) !== 0x02014b50) break;
      const nameLen = dv.getUint16(p + 28, true);
      const extraLen = dv.getUint16(p + 30, true);
      const commentLen = dv.getUint16(p + 32, true);
      if (p + 46 + nameLen > bytes.length) break;
      const name = dec.decode(bytes.subarray(p + 46, p + 46 + nameLen));
      names.add(name);
      p += 46 + nameLen + extraLen + commentLen;
    }
    return names.size ? names : null;
  }

  // ── Bootstrap: attach `static EXTS` and `static canHandle(ctx)` to each
  //    renderer class so callers can query detection at the class level
  //    (`PdfRenderer.canHandle(ctx)` / `PdfRenderer.EXTS`). Each renderer 
  //    is self-contained; the registry is the one authorised place that
  //    mutates them, and it only adds read-only detection metadata
  //    — it never alters render/analyze behaviour.
  static _bootstrap() {
    for (const e of this.ENTRIES) {
      const cls = (typeof globalThis !== 'undefined') ? globalThis[e.className] : undefined;
      if (!cls) continue;
      // Preserve any existing (per-renderer) canHandle — a renderer is
      // free to override the default with its own logic if registered.
      if (!cls.EXTS) cls.EXTS = e.exts.slice();
      if (!cls.canHandle) {
        const id = e.id;
        cls.canHandle = function (ctx) { return RendererRegistry.canHandle(id, ctx); };
      }
    }
  }
}

// Run the bootstrap immediately — by the time this file is concatenated
// into docs/index.html every renderer class has already been defined.
RendererRegistry._bootstrap();
