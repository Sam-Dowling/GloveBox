// binary-strings.js — Categorised string classification for native binaries.
//
// The PE / ELF / Mach-O renderers already extract ASCII + UTF-16LE string
// dumps during parsing. Those dumps get hashed through the URL + UNC regex
// today but *everything else* of forensic interest (mutex names,
// Windows named pipes, PDB build-host paths, registry keys, user-home
// paths) is invisible to the sidebar IOC table. That is attribution and
// pivot gold: a PDB path like
// `C:\Users\actor\source\stealer\x64\Release\stealer.pdb` tells you the
// build username, the project name and the toolchain; a mutex name like
// `Global\\SessionHost_7B23` is a direct cluster key for sibling samples.
//
// This helper takes the already-collected string corpus and surfaces each
// of those forensic categories as a separate list, de-duped and capped.
// The renderers push them onto `findings.interestingStrings` via
// `pushIOC()` with the correct `IOC.*` type so the sidebar filtering
// treats them as first-class IOCs.
//
// Contract
// --------
//   BinaryStrings.classify(strings)
//     → { mutexes: string[], namedPipes: string[],
//         pdbPaths: string[], userPaths: string[],
//         registryPaths: string[] }
//
// All categories are de-duplicated. Caller supplies its own per-category
// cap when pushing to findings — we return the full list so a caller can
// emit a truncation-marker `IOC.INFO` row when the cap is hit.
//
// Design constraints
// ------------------
// • PE-only patterns (mutex / pipe / registry) will also never match the
//   ELF / Mach-O string corpora, so the helper is safe to call from all
//   three renderers — each category's hit list is trivially empty on
//   non-matching formats.
// • Regexes are deliberately tight (anchored, length-bounded) because
//   the string dumps contain a *lot* of false-positive-ish data (CLR
//   resource-table fragments, version-info UTF-16 blobs, obfuscated-but-
//   printable PE section names, …). A loose mutex regex would flag half
//   the import table.
// • Input is always treated as `\n`-joined — `extractAsciiAndUtf16leStrings`
//   in constants.js already terminates each extracted string with a
//   newline. For raw array input we join the same way.

const BinaryStrings = (() => {

  // Per-category hit caps — mirror the URL/UNC caps used in the three
  // binary renderers so the sidebar doesn't drown a triage pass in a
  // dumped resource table's worth of printable garbage.
  const CAPS = {
    mutex:     30,
    pipe:      30,
    pdb:       20,
    userPath:  30,
    registry:  30,
    rustPanic: 20,
  };

  // ── Patterns ────────────────────────────────────────────────────────
  //
  // Each regex matches the *whole* occurrence on a string that may be
  // surrounded by any amount of printable padding. We use `gm` so the
  // `^` / `$` anchors are per-line (strings are `\n`-joined).

  // Mutexes: `Global\Foo`, `Local\Bar`, `Session\N\Baz`. The backslash
  // may also appear doubled (`Global\\Foo`) when the string was embedded
  // in C-source style escapes — accept both.
  //
  // Length bounds (2..120) reject the two dominant false-positive shapes:
  //   • `Global\s` (single-char tail — common shell-word fragment)
  //   • 200+ byte junk strings (.rsrc / .rdata version blobs)
  const MUTEX_RX = /\b(?:Global|Local|Session)\\{1,2}[A-Za-z0-9][A-Za-z0-9._\-{}()$ ]{2,120}/g;

  // Windows named pipes: `\\.\pipe\name`, `\\?\pipe\name`. The name
  // portion tolerates the same character class as mutexes. Match the full
  // path verbatim (we want the exact string the binary is holding).
  const PIPE_RX = /\\\\[.?]\\pipe\\[A-Za-z0-9][A-Za-z0-9._\-$]{2,120}/g;

  // PDB paths — both Windows-style absolute paths and `srcsrv`-style
  // POSIX paths that modern llvm/lld produces. Require `.pdb` at the tail.
  //
  // Windows: `C:\proj\foo\bar.pdb`
  // POSIX  : `/home/build/foo/bar.pdb`
  const PDB_WIN_RX = /\b[A-Za-z]:\\(?:[^\\\/<>:"|?*\r\n\x00]+\\)+[^\\\/<>:"|?*\r\n\x00]+\.pdb\b/g;
  const PDB_NIX_RX = /(?:^|[\s"'>:])(\/(?:[^\s"'<>|?*\r\n\x00]+\/)+[^\s"'<>|?*\r\n\x00]+\.pdb)\b/g;

  // User-home / build-host Windows paths — strong attribution signal.
  // The PDB rx picks up `*.pdb`; this one picks up everything else in the
  // user-identifying path space (source roots, release trees, …).
  //
  // Start anchors: drive-letter + `Users\` / `Dev\` / `Source\` /
  // `Projects\` / `Build\` / `repos\` / `git\` / `src\` (case-insensitive).
  // Followed by ≥ 1 path segment so we don't capture the bare root.
  const USER_WIN_RX = /\b[A-Za-z]:\\(?:Users|Dev|Source|Sources|Projects|Builds?|repos?|git|src)\\[^<>:"|?*\r\n\x00]{3,200}/gi;
  // POSIX equivalent — /home/<user>/… or /Users/<user>/… or /root/…
  // Capture tight `.src`-style paths too (used for Rust source-file leaks;
  // a dedicated Rust-panic miner lives below — this rx is about the
  // bare build-host attribution.)
  const USER_NIX_RX = /(?:^|[\s"'>:])(\/(?:home|Users|root|opt|srv)\/[^\s"'<>|?*\r\n\x00]{3,200})/g;

  // Registry keys — `HKLM\…`, `HKCU\…`, `HKEY_LOCAL_MACHINE\…`, etc.
  // Anchor on the hive prefix; require ≥ 1 subkey component. The match
  // group is the entire key path including the hive so the sidebar row
  // is usable as-is.
  const REGISTRY_RX = /\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\(?:[A-Za-z0-9 _.\-]+\\){1,12}[A-Za-z0-9 _.\-]{1,80}/g;

  // Rust panic sources — strong attribution + toolchain signal.
  //
  // When a Rust binary is compiled without `strip = "symbols"` (the
  // default for `cargo build`), the `panicked at '...', src/foo.rs:42:5`
  // literals survive into `.rdata` / `__rodata` and leak:
  //   • the exact `.rs` source path the panic!() macro was expanded in
  //   • often the build-host absolute prefix on nightly toolchains
  //   • the library / crate name via the `/rustc/<hash>/library/…`
  //     pattern (the Rust compiler's own stdlib)
  //
  // The regex matches both the classic Rust ≤ 1.72 shape:
  //   `panicked at 'assertion failed', src/lib.rs:42:9`
  // and the modern Rust ≥ 1.73 shape (no quoted message, different order):
  //   `panicked at src/lib.rs:42:9:\nassertion failed`
  //
  // Capture group 1 is the `.rs` source path — that's what we surface as
  // the IOC; the full match is kept for the `note` field so the analyst
  // can see the surrounding panic context at a glance.
  const RUST_PANIC_RX = /panicked at (?:'[^'\n]{0,200}', )?((?:\/|[A-Za-z]:\\)?[^\s"'<>|?*\r\n\x00]{1,200}\.rs):\d+:\d+/g;

  // ── Helpers ─────────────────────────────────────────────────────────
  function _normLines(strings) {
    if (Array.isArray(strings)) return strings.join('\n');
    return String(strings || '');
  }

  function _collect(corpus, rx, opts) {
    opts = opts || {};
    const group = opts.group || 0;
    const out = new Set();
    let m;
    rx.lastIndex = 0;
    while ((m = rx.exec(corpus)) !== null) {
      let v = (group > 0 ? m[group] : m[0]);
      if (!v) continue;
      v = v.trim();
      // Strip trailing punctuation that commonly attaches to paths in
      // binary strings (`"`, `'`, `)`, `:`, `,`, `;`).
      v = v.replace(/[)\]}>"'`,;:]+$/, '');
      if (!v) continue;
      // Reject clearly-UI strings — anything without at least one letter
      // + one digit/separator is usually a format-string fragment.
      if (opts.requireMixed && !/[A-Za-z]/.test(v)) continue;
      out.add(v);
    }
    return [...out];
  }

  function classify(strings) {
    const corpus = _normLines(strings);
    return {
      mutexes:       _collect(corpus, MUTEX_RX,    { requireMixed: true }),
      namedPipes:    _collect(corpus, PIPE_RX,     { requireMixed: true }),
      pdbPaths:      [
        ..._collect(corpus, PDB_WIN_RX, { requireMixed: true }),
        ..._collect(corpus, PDB_NIX_RX, { requireMixed: true, group: 1 }),
      ],
      userPaths:     [
        ..._collect(corpus, USER_WIN_RX, { requireMixed: true }),
        ..._collect(corpus, USER_NIX_RX, { requireMixed: true, group: 1 }),
      ],
      registryPaths: _collect(corpus, REGISTRY_RX, { requireMixed: true }),
      rustPanics:    _collect(corpus, RUST_PANIC_RX, { requireMixed: true, group: 1 }),
    };
  }

  /**
   * Convenience helper used by all three renderers — classifies the
   * string corpus, then emits each category as the appropriate IOC.*
   * type via `pushIOC()`, respecting per-category caps and pushing an
   * `IOC.INFO` truncation-marker row when the full list was trimmed.
   *
   * @param {object} findings   — as built by `analyzeForSecurity`
   * @param {string[]|string} strings — the renderer's combined string corpus
   * @param {object} [_opts]    — reserved (no options today)
   * @returns {object} the category counts, e.g. `{mutexes:3, namedPipes:0,…}`
   *   so the caller can populate `findings.metadata` summary rows.
   */
  function emit(findings, strings) {
    const cats = classify(strings);
    const counts = {
      mutexes: cats.mutexes.length,
      namedPipes: cats.namedPipes.length,
      pdbPaths: cats.pdbPaths.length,
      userPaths: cats.userPaths.length,
      registryPaths: cats.registryPaths.length,
      rustPanics: cats.rustPanics.length,
    };
    if (typeof pushIOC !== 'function') return counts;

    const pushCapped = (list, cap, type, note, severity, label) => {
      for (const v of list.slice(0, cap)) {
        pushIOC(findings, {
          type, value: v, severity, highlightText: v, note,
          _noDomainSibling: true,
        });
      }
      if (list.length > cap) {
        pushIOC(findings, {
          type: (typeof IOC !== 'undefined' && IOC && IOC.INFO) || 'Info',
          value: `${label} truncated at ${cap} — binary contains ${list.length} unique entries`,
          severity: 'info',
        });
      }
    };

    const _P = (typeof IOC !== 'undefined' && IOC && IOC.PATTERN)   || 'Pattern';
    const _F = (typeof IOC !== 'undefined' && IOC && IOC.FILE_PATH) || 'File Path';
    const _R = (typeof IOC !== 'undefined' && IOC && IOC.REGISTRY_KEY) || 'Registry Key';

    pushCapped(cats.mutexes,       CAPS.mutex,    _P, 'Windows mutex name (cluster key / defence-evasion marker, T1027)', 'medium', 'Mutexes');
    pushCapped(cats.namedPipes,    CAPS.pipe,     _P, 'Windows named pipe (lateral-movement / IPC, T1559.001)',           'medium', 'Named pipes');
    pushCapped(cats.pdbPaths,      CAPS.pdb,      _F, 'PDB path (debug-info — build-host attribution leak)',              'info',   'PDB paths');
    pushCapped(cats.userPaths,     CAPS.userPath, _F, 'User-home / build-tree path (attribution leak)',                   'info',   'Build-host paths');
    pushCapped(cats.registryPaths, CAPS.registry, _R, 'Registry key reference (persistence / config, T1547.001)',         'medium', 'Registry keys');
    // Rust panic-source paths are attribution gold — they leak the
    // build-host source tree and often the crate name. Emit as FILE_PATH
    // info-tier so they're pivotable in the sidebar without bumping risk.
    pushCapped(cats.rustPanics,    CAPS.rustPanic, _F, 'Rust panic source path (toolchain attribution leak)',              'info',   'Rust panic paths');

    return counts;
  }

  // ── Viewer helper ───────────────────────────────────────────────────
  //
  // renderCategorisedStringsTable(strings, [opts]) → HTMLElement | null
  //
  // Returns a compact "Categorised strings" preview card the three
  // native-binary renderers prepend to their 🔤 Strings view. Six
  // sections:
  //   • Mutexes        (synchronisation / cluster keys — T1027)
  //   • Named Pipes    (IPC / lateral movement — T1559.001)
  //   • Registry Keys  (persistence / config — T1547.001)
  //   • PDB Paths      (build-host attribution)
  //   • User / Build Paths   (build-tree attribution)
  //   • Rust Panic Paths     (rustc source-file leaks)
  //
  // Each section is a `<details>` collapsed-by-default, expanding into
  // a monospaced list of the (deduped, capped) entries. When every
  // category is empty the function returns null so callers can
  // conditionally skip the card.
  //
  // Pure presentation — the helper does NOT touch `findings` (emit()
  // already pushed each entry as the correct IOC.* type).
  const _esc = escHtml;

  function renderCategorisedStringsTable(strings, _opts) {
    const cats = classify(strings);
    const sections = [
      { key: 'mutexes',       label: '🔒 Mutexes',           note: 'synchronisation / cluster keys (T1027)',     cap: CAPS.mutex,     items: cats.mutexes     },
      { key: 'namedPipes',    label: '🪈 Named Pipes',       note: 'IPC / lateral movement (T1559.001)',         cap: CAPS.pipe,      items: cats.namedPipes  },
      { key: 'registryPaths', label: '🗝 Registry Keys',     note: 'persistence / config (T1547.001)',           cap: CAPS.registry,  items: cats.registryPaths },
      { key: 'pdbPaths',      label: '🧩 PDB Paths',         note: 'debug-info (build-host attribution)',        cap: CAPS.pdb,       items: cats.pdbPaths    },
      { key: 'userPaths',     label: '🏠 User / Build Paths', note: 'build-tree attribution',                    cap: CAPS.userPath,  items: cats.userPaths   },
      { key: 'rustPanics',    label: '🦀 Rust Panic Paths',  note: 'rustc source-file leaks',                    cap: CAPS.rustPanic, items: cats.rustPanics  },
    ];
    const anyHits = sections.some(s => s.items.length);
    if (!anyHits) return null;

    const card = document.createElement('div');
    card.className = 'bin-strings-cats';

    const hdr = document.createElement('div');
    hdr.className = 'bin-strings-cats-hdr';
    hdr.textContent = '🧭 Categorised strings (triage preview)';
    card.appendChild(hdr);

    const sub = document.createElement('div');
    sub.className = 'bin-strings-cats-sub';
    sub.textContent = 'Forensically-relevant string categories auto-classified from the binary\'s ASCII + UTF-16LE corpus. Full lists are also emitted as IOCs in the sidebar.';
    card.appendChild(sub);

    for (const s of sections) {
      if (!s.items.length) continue;
      const det = document.createElement('details');
      det.className = 'bin-strings-cat';
      const sum = document.createElement('summary');
      sum.className = 'bin-strings-cat-sum';
      const capped = s.items.length > s.cap;
      const shown = capped ? s.cap : s.items.length;
      sum.innerHTML =
        '<span class="bin-strings-cat-label">' + _esc(s.label) + '</span>' +
        ' <span class="bin-strings-cat-count">(' + shown +
        (capped ? ' of ' + s.items.length : '') +
        ')</span>' +
        ' <span class="bin-strings-cat-note">' + _esc(s.note) + '</span>';
      det.appendChild(sum);
      const list = document.createElement('ul');
      list.className = 'bin-strings-cat-list';
      for (const v of s.items.slice(0, s.cap)) {
        const li = document.createElement('li');
        li.className = 'bin-strings-cat-item';
        li.textContent = v;
        list.appendChild(li);
      }
      if (capped) {
        const li = document.createElement('li');
        li.className = 'bin-strings-cat-trunc';
        li.textContent = '… ' + (s.items.length - s.cap) + ' more (see sidebar IOCs)';
        list.appendChild(li);
      }
      det.appendChild(list);
      card.appendChild(det);
    }
    return card;
  }

  return { classify, emit, CAPS, renderCategorisedStringsTable };
})();


if (typeof window !== 'undefined') window.BinaryStrings = BinaryStrings;
