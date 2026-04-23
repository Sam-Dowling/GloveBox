// binary-summary.js — Shared "binary pivot" triage card for PE / ELF / Mach-O.
//
// The three native-binary renderers each emit several large sections
// (headers / sections / imports / exports / resources / strings / YARA).
// An analyst triaging a sample almost always wants the same handful of
// fields *before* scrolling into any of that detail:
//
//   - File hash trio (MD5 / SHA-1 / SHA-256)  — VT / Malpedia / MB pivots.
//   - Import-shape hash (imphash / telfhash / Mach-O import-hash) — family
//     clustering. Plus RichHash (PE) and SymHash (Mach-O).
//   - Signer / "unsigned" — Authenticode CN for PE, code-signature Team ID
//     or leaf CN for Mach-O, "—" for ELF.
//   - Compile timestamp + "faked?" flag — 1970 zero, 0xFFFFFFFF invalid,
//     Borland TLINK default (0x2A425E19), future-dated, pre-2000, and the
//     Feb 2006 "reproducible-build" sentinel rustc/lld emit.
//   - Entry-point section + anomaly flag — orphan EP, EP in W+X section,
//     EP outside a canonical code section (see `_analyzeEntryPoint` in
//     pe-renderer.js).
//   - Overlay Y/N + first-bytes magic — from `BinaryOverlay.compute()`.
//   - Packer verdict — canonical section-name hit (UPX0 / .themida / …),
//     captured during the per-format section parse.
//   - Per-format identity rows: .NET CLR runtime (PE), GNU build-id (ELF),
//     Team ID / Bundle ID / SDK-MinOS (Mach-O). Each is a single row,
//     emitted only when the underlying datum was successfully parsed, so
//     the card stays short on the (common) case where none apply.
//
// This helper renders all of the above as one uniform card so the layout
// is identical across PE / ELF / Mach-O. It never mutates `findings` —
// that is still the responsibility of each renderer's
// `analyzeForSecurity()` pass. The card is pure presentation.
//
// Contract
// --------
//   BinarySummary.renderCard({
//     bytes,                   Uint8Array of the full file.
//     fileSize,                file length in bytes (bytes.length).
//     format,                  'PE' / 'ELF' / 'Mach-O'.
//     formatDetail,            caller-chosen short format string (e.g.
//                              'PE32+ · x86-64', 'ELF64 · x86-64',
//                              'Mach-O 64-bit · arm64').
//     importHash,              imphash / telfhash / Mach-O import hash.
//     richHash,                PE-only (nullable).
//     symHash,                 Mach-O-only (nullable).
//     signer,                  { present: bool, verified?: bool,
//                              label: string } — label like
//                              'CN=Foo Corp' or 'Team ID: A1B2C3…' or
//                              'Ad-hoc signed'. `verified` is a tri-state
//                              hint for whether the signature's
//                              certificate chain has been structurally
//                              validated. Loupe is offline so the CMS
//                              root-of-trust is not walked; the flag is
//                              therefore almost always absent or false.
//                              When `present: true && !verified` the
//                              badge reads "signer present" rather than
//                              "signed" — we surface that a signature
//                              blob exists without over-claiming that
//                              it has been trust-validated.
//     compileTimestamp,        { epoch, displayStr } — PE only. null on
//                              ELF / Mach-O (neither format carries a
//                              compile timestamp in its structural header).
//     entryPoint,              { displayStr, section, anomaly } — the
//                              `anomaly` string is a short human flag
//                              like 'orphaned' / 'W+X' / 'non-.text'.
//     overlay,                 { present, size, label } or null. `label`
//                              is the sniffed first-bytes magic (e.g.
//                              'PE (MZ)', 'ZIP / PK', 'ASN.1 DER').
//     packer,                  { label: string, source: string } or null.
//                              `source` is a short provenance hint like
//                              'section .UPX0' or 'strings UPX!'.
//     teamId,                  Mach-O code-signature Team ID, e.g.
//                              'A1B2C3D4E5'. Rendered as its own row so
//                              the 10-char identifier is copy-friendly
//                              even when the signer label is long.
//     bundleId,                Mach-O CFBundleIdentifier harvested from
//                              an embedded Info.plist (usually surfaced
//                              as `findings.metadata['Bundle ID']` by
//                              the renderer).
//     buildId,                 ELF `.note.gnu.build-id` hex digest —
//                              the durable attribution tell even after
//                              `strip` has removed debuginfo. Pair with
//                              debuginfod / `/usr/lib/debug/.build-id/`.
//     clrRuntime,              PE .NET CLR metadata runtime-version
//                              string, e.g. 'v4.0.30319' (distinguishes
//                              .NET Framework 2/4, .NET Core, etc.).
//     sdkMinOS,                Mach-O `LC_BUILD_VERSION` /
//                              `LC_VERSION_MIN_*` triple as a single
//                              compact string like 'macOS 13.0 · SDK
//                              14.0'.
//   }) → HTMLElement
//
// The MD5 / SHA-1 / SHA-256 placeholders are filled in asynchronously:
//   - SHA-1 + SHA-256 via `crypto.subtle.digest` (CSP-safe, same path the
//     overlay card uses for its overlay hash).
//   - MD5 via the shared `md5()` in `hashes.js`. Pure JS, synchronous for
//     small files, but wrapped in a 0-timeout so a 500 MB sample doesn't
//     block the main thread while the card is painting.
//
// Load order: `src/hashes.js` must be concatenated BEFORE this file in
// `scripts/build.py` so `md5` is defined at renderCard time. The helper
// is itself loaded BEFORE the three native renderers.

const BinarySummary = (() => {

  // ── Timestamp anomaly detection ─────────────────────────────────────────
  //
  // Sentinel values malware tooling hard-codes instead of letting the
  // linker stamp a real date. Keeping this Map tiny and well-known — we
  // would rather under-report than invent false positives. The other two
  // checks (future-dated, pre-2000) cover the broad "this is obviously
  // not a real compile time" cases.
  const SENTINEL_TIMESTAMPS = new Map([
    [0,          'zeroed (epoch)'],
    [0xFFFFFFFF, 'invalid (0xFFFFFFFF)'],
    [0x2A425E19, 'Borland TLINK default'],
  ]);

  // Rustc / lld "deterministic build" epoch: Sun 05 Feb 2006 00:00:00 UTC
  // ±1 day (1139097600 ± 86400). Older Rust toolchains, Wix, and a handful
  // of reproducible-build pipelines stamp binaries with this fixed date so
  // byte-identical rebuilds are possible; it is the single most common
  // "fake but non-zero" timestamp in modern samples.
  const REPRODUCIBLE_2006_LO = 1139011200; // 2006-02-04 00:00 UTC
  const REPRODUCIBLE_2006_HI = 1139184000; // 2006-02-06 00:00 UTC

  function detectFakedTimestamp(ts) {
    if (ts == null) return null;
    const sentinel = SENTINEL_TIMESTAMPS.get(ts >>> 0);
    if (sentinel) return sentinel;
    const nowSec = Math.floor(Date.now() / 1000);
    if (ts > nowSec + 86400) return 'future-dated';
    if (ts < 946684800) return 'pre-2000 (likely forged)';
    if (ts >= REPRODUCIBLE_2006_LO && ts < REPRODUCIBLE_2006_HI) {
      return 'Feb 2006 reproducible-build epoch';
    }
    return null;
  }

  // ── crypto.subtle wrappers ──────────────────────────────────────────────
  async function _subtleHex(algo, u8) {
    try {
      const view = (u8.byteOffset === 0 && u8.byteLength === u8.buffer.byteLength)
        ? u8.buffer
        : u8.slice().buffer;
      const digest = await crypto.subtle.digest(algo, view);
      const bytes = new Uint8Array(digest);
      let hex = '';
      for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
      return hex;
    } catch (_) {
      return null;
    }
  }

  // ── Helpers ─────────────────────────────────────────────────────────────
  const _esc = escHtml;

  const _fmtBytes = fmtBytes;

  function _row(label, valueHtml, badgeHtml) {
    const row = document.createElement('div');
    row.className = 'bin-summary-row';
    const l = document.createElement('div');
    l.className = 'bin-summary-label';
    l.textContent = label;
    const v = document.createElement('div');
    v.className = 'bin-summary-value';
    v.innerHTML = valueHtml + (badgeHtml ? ' ' + badgeHtml : '');
    row.appendChild(l);
    row.appendChild(v);
    return row;
  }

  function _hashRow(label, algo, bytes) {
    const row = document.createElement('div');
    row.className = 'bin-summary-row';
    const l = document.createElement('div');
    l.className = 'bin-summary-label';
    l.textContent = label;
    const v = document.createElement('div');
    v.className = 'bin-summary-value bin-summary-hash';
    v.textContent = 'computing…';
    row.appendChild(l);
    row.appendChild(v);
    if (algo === 'MD5') {
      // md5() is synchronous pure JS. For anything below a few MiB it
      // completes well under a frame; for larger inputs we still want it
      // off the painting path, so defer a tick.
      setTimeout(() => {
        try {
          const hex = (typeof md5 === 'function') ? md5(bytes) : null;
          v.textContent = hex || '—';
        } catch (_) {
          v.textContent = '—';
        }
      }, 0);
    } else {
      _subtleHex(algo, bytes).then(hex => { v.textContent = hex || '—'; });
    }
    return row;
  }

  function _badge(text, kind) {
    const span = document.createElement('span');
    span.className = 'bin-summary-badge' + (kind ? ' bin-summary-badge-' + kind : '');
    span.textContent = text;
    return span.outerHTML;
  }

  // ── Public API ──────────────────────────────────────────────────────────
  /**
   * Build the Binary Pivot card.
   * Returns an HTMLElement ready to append to the renderer's output.
   */
  function renderCard(opts) {
    const {
      bytes, fileSize, format, formatDetail,
      importHash, richHash, symHash,
      signer, compileTimestamp, entryPoint, overlay, packer,
      teamId, bundleId, buildId, clrRuntime, sdkMinOS,
    } = opts || {};

    const card = document.createElement('div');
    card.className = 'bin-summary-card';

    const header = document.createElement('div');
    header.className = 'bin-summary-header';
    header.textContent = '🧬 Binary Pivot';
    card.appendChild(header);

    const body = document.createElement('div');
    body.className = 'bin-summary-body';

    // ── File hashes (async) ───────────────────────────────────────────────
    body.appendChild(_hashRow('SHA-256',   'SHA-256', bytes));
    body.appendChild(_hashRow('SHA-1',     'SHA-1',   bytes));
    body.appendChild(_hashRow('MD5',       'MD5',     bytes));

    // ── Format / architecture ─────────────────────────────────────────────
    const fmt = _esc(format || '—');
    const detail = formatDetail ? ' · ' + _esc(formatDetail) : '';
    body.appendChild(_row('Format', `<strong>${fmt}</strong>${detail} · ${_fmtBytes(fileSize || (bytes ? bytes.length : 0))}`));

    // ── Import-shape hashes ───────────────────────────────────────────────
    if (importHash) body.appendChild(_row('Import Hash', `<code>${_esc(importHash)}</code>`));
    if (richHash)   body.appendChild(_row('RichHash',    `<code>${_esc(richHash)}</code>`));
    if (symHash)    body.appendChild(_row('SymHash',     `<code>${_esc(symHash)}</code>`));

    // ── Signer ────────────────────────────────────────────────────────────
    // Tri-state presentation:
    //   { present:false }                 → "unsigned" (warn)
    //   { present:true,  verified:true }  → "signed" (ok)
    //   { present:true,  verified:false } → "signer present" (info)
    //                                       — blob parsed, chain not
    //                                       walked (Loupe is offline,
    //                                       so the CMS root-of-trust
    //                                       cannot be validated).
    //   { present:true } with no verified → same as !verified (the safe
    //                                       default — never claim
    //                                       "signed" without evidence).
    if (signer) {
      let badgeText, badgeKind;
      if (!signer.present) {
        badgeText = 'unsigned';   badgeKind = 'warn';
      } else if (signer.verified) {
        badgeText = 'signed';     badgeKind = 'ok';
      } else {
        badgeText = 'signer present'; badgeKind = 'info';
      }
      const sBadge = _badge(badgeText, badgeKind);
      body.appendChild(_row('Signer', _esc(signer.label || (signer.present ? 'signer present' : '—')), sBadge));
    }

    // ── Mach-O Team ID (separate row — copy-friendly) ─────────────────────
    // The Team ID already appears inside the signer label, but analysts
    // routinely grep the 10-char identifier on its own (it's the pivot
    // into Apple Developer registration and MITRE T1553.002 clusters),
    // so a dedicated `<code>`-formatted row keeps it selectable without
    // the 'Team ID: ' prefix.
    if (teamId) {
      body.appendChild(_row('Team ID', `<code>${_esc(teamId)}</code>`));
    }

    // ── Mach-O Bundle ID / ELF build-id / PE CLR runtime ──────────────────
    // One compact identity row per format; each is a durable attribution
    // tell that survives stripping (build-id lives in a note section,
    // bundle-id lives in Info.plist, CLR runtime lives in the COR20
    // header). Only one of these is ever non-null per sample.
    if (bundleId)   body.appendChild(_row('Bundle ID',   `<code>${_esc(bundleId)}</code>`));
    if (buildId)    body.appendChild(_row('Build ID',    `<code>${_esc(buildId)}</code>`));
    if (clrRuntime) body.appendChild(_row('CLR Runtime', `<code>${_esc(clrRuntime)}</code>`));
    if (sdkMinOS)   body.appendChild(_row('SDK / Min OS', _esc(sdkMinOS)));

    // ── Compile timestamp (PE only; ELF/Mach-O skip) ──────────────────────
    if (compileTimestamp && compileTimestamp.displayStr) {
      const faked = compileTimestamp.fakedReason
        || detectFakedTimestamp(compileTimestamp.epoch);
      const badge = faked ? _badge('⚠ ' + faked, 'warn') : '';
      body.appendChild(_row('Compiled', _esc(compileTimestamp.displayStr), badge));
    }

    // ── Entry point + anomaly ─────────────────────────────────────────────
    if (entryPoint && entryPoint.displayStr) {
      const badge = entryPoint.anomaly ? _badge('⚠ ' + entryPoint.anomaly, 'warn') : '';
      const secStr = entryPoint.section ? ' in <code>' + _esc(entryPoint.section) + '</code>' : '';
      body.appendChild(_row('Entry Point', `<code>${_esc(entryPoint.displayStr)}</code>${secStr}`, badge));
    }

    // ── Overlay ───────────────────────────────────────────────────────────
    if (overlay && overlay.present) {
      const sz = typeof overlay.size === 'number' ? _fmtBytes(overlay.size) : '';
      const lab = overlay.label ? ' — ' + _esc(overlay.label) : '';
      const badge = _badge('present', 'warn');
      body.appendChild(_row('Overlay', `${sz}${lab}`, badge));
    } else {
      body.appendChild(_row('Overlay', '<span class="bin-summary-muted">none</span>'));
    }

    // ── Packer ────────────────────────────────────────────────────────────
    if (packer && packer.label) {
      const src = packer.source ? ` <span class="bin-summary-muted">(${_esc(packer.source)})</span>` : '';
      const badge = _badge('packed', 'warn');
      body.appendChild(_row('Packer', `<strong>${_esc(packer.label)}</strong>${src}`, badge));
    }

    card.appendChild(body);
    return card;
  }

  return {
    renderCard,
    detectFakedTimestamp,
    SENTINEL_TIMESTAMPS,
  };

})();
