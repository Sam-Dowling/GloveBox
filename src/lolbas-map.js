'use strict';
// ════════════════════════════════════════════════════════════════════════════
// lolbas-map.js — Living-Off-The-Land Binaries And Scripts → ATT&CK lookup.
//
// Ad-hoc string matching for LOLBAS binaries is sprinkled across
// half-a-dozen renderers (cmd-obfuscation.js, inf-renderer.js, lnk-renderer.js,
// reg-renderer.js, html-renderer.js, …). This file gives those callers ONE
// canonical, structured reference: name → { binary, tactics, attack, note }.
//
// Coverage scope:
//   The canonical "high-signal" subset. Full LOLBAS catalog is ~190 entries
//   (see lolbas-project.github.io); ≥95 % of incident-report mentions of
//   LOLBAS binaries land on the ~30 here. New entries belong here only when
//   we have a corresponding renderer or detector that would surface them.
//
// `attack` is a list of MITRE ATT&CK technique IDs already declared in
// src/mitre.js. The scanner returns these as plain strings — callers can
// look up display names via `MITRE.byId(id)` if they need them in the UI.
//
// Used by: any renderer that surfaces command-line / executable references
// Depends on: nothing (pure data + a literal-substring scanner)
// ════════════════════════════════════════════════════════════════════════════

const LOLBAS_MAP = (() => {
  // Small helper to build a freeze-once row. Severity is the floor that the
  // mere presence of this binary in a hostile context should imply — most
  // are 'high' because the binary itself is signed and thus its presence
  // bypasses AppLocker's publisher policy. 'critical' is reserved for
  // execution primitives that have NO legitimate non-attacker use case in
  // the file types Loupe analyses (e.g. mshta.exe in a .url / .lnk).
  function row(binary, attack, severity, note) {
    return Object.freeze({ binary, attack: Object.freeze(attack), severity, note });
  }

  return Object.freeze({
    // Filename match table. Keys are lowercase, with-extension. The scanner
    // also accepts both full paths and bare names.
    //
    // ── System-binary proxy execution (T1218 family) ──────────────────────
    'mshta.exe':       row('mshta.exe',       ['T1218.005'], 'critical', 'Executes HTA / inline script — full system access on launch'),
    'rundll32.exe':    row('rundll32.exe',    ['T1218.011'], 'high',     'Proxy-executes any DLL export — common downloader stage'),
    'regsvr32.exe':    row('regsvr32.exe',    ['T1218.010'], 'high',     'Squiblydoo: /i:URL scrobj.dll fetches+runs remote .sct script'),
    'odbcconf.exe':    row('odbcconf.exe',    ['T1218.008'], 'high',     'REGSVR action runs DLL exports; signed-binary AppLocker bypass'),
    'cmstp.exe':       row('cmstp.exe',       ['T1218.003'], 'high',     'Loads attacker INF over HTTPS, executes embedded scriptlet'),
    'installutil.exe': row('installutil.exe', ['T1218.004'], 'high',     'Runs uninstaller method of arbitrary .NET assembly'),
    'msiexec.exe':     row('msiexec.exe',     ['T1218.007'], 'high',     '/i URL fetches and installs remote .msi (T1218.007)'),
    'msbuild.exe':     row('msbuild.exe',     ['T1127.001'], 'high',     'Compiles+executes inline C# from XML project file'),
    'forfiles.exe':    row('forfiles.exe',    ['T1218'],     'medium',   'Spawns child processes; sandbox/AV-evasion launcher'),
    'wscript.exe':     row('wscript.exe',     ['T1059.005'], 'high',     'Windows Script Host — JScript/VBScript execution'),
    'cscript.exe':     row('cscript.exe',     ['T1059.005'], 'high',     'Windows Script Host (console) — JScript/VBScript execution'),

    // ── PowerShell / CLI shells (T1059) ───────────────────────────────────
    'powershell.exe':  row('powershell.exe',  ['T1059.001'], 'high',     'Encoded / downloaded payload execution; highly abused'),
    'pwsh.exe':        row('pwsh.exe',        ['T1059.001'], 'high',     'PowerShell Core — same abuse surface as powershell.exe'),
    'cmd.exe':         row('cmd.exe',         ['T1059.003'], 'medium',   'Command shell — most-used staging primitive'),

    // ── Ingress tool transfer (T1105) ─────────────────────────────────────
    'certutil.exe':    row('certutil.exe',    ['T1105', 'T1140'], 'high', 'Downloads files (-urlcache) and decodes base64 (-decode)'),
    'bitsadmin.exe':   row('bitsadmin.exe',   ['T1105'], 'high', 'Background Intelligent Transfer fetch — survives reboots'),
    'curl.exe':        row('curl.exe',        ['T1105'], 'medium', 'Stock download utility (Windows ≥1803); preferred fetcher'),
    'finger.exe':      row('finger.exe',      ['T1105'], 'high', 'TCP/79 payload exfil/fetch — virtually no legit use today'),
    'tftp.exe':        row('tftp.exe',        ['T1105'], 'high', 'UDP/69 fetch — minimal protocol, evades many proxies'),
    'esentutl.exe':    row('esentutl.exe',    ['T1105'], 'high', 'Native ESE engine — copies files via /vss /y /d, downloads via WebDAV'),

    // ── Scheduled-task / persistence (T1053) ──────────────────────────────
    'schtasks.exe':    row('schtasks.exe',    ['T1053.005'], 'medium', 'Creates Scheduled Task — common persistence step'),
    'at.exe':          row('at.exe',          ['T1053.002'], 'medium', 'Legacy AT scheduler (deprecated) — when seen, is suspicious'),

    // ── WMI / management (T1047, T1218.014) ───────────────────────────────
    'wmic.exe':        row('wmic.exe',        ['T1047', 'T1220'], 'high', 'WMI command + /format:URL SquiblyTwo XSL fetch+execute'),

    // ── Reg / system internals (T1112, T1547) ─────────────────────────────
    'reg.exe':         row('reg.exe',         ['T1112'], 'medium', 'Registry-write primitive — Run-key persistence is most common'),

    // ── Process injection-adjacent / stealth (T1620, T1218.014) ───────────
    'msxsl.exe':       row('msxsl.exe',       ['T1220'], 'high', 'Standalone XSLT processor — SquiblyTwo signed-proxy execution'),

    // ── DefenderControl / dual-use ────────────────────────────────────────
    'msdt.exe':        row('msdt.exe',        ['T1218'], 'high', 'Follina (CVE-2022-30190) — IT_BrowseForFile= path-substituted RCE'),

    // ── Unsigned but ubiquitous ───────────────────────────────────────────
    'hh.exe':          row('hh.exe',          ['T1218.001'], 'high', 'CHM viewer — InfoTech: scheme runs HTML+script with full trust'),
    'ie4uinit.exe':    row('ie4uinit.exe',    ['T1546.015'], 'high', 'COM-hijack via -BaseSettings — UAC bypass / persistence'),
    'control.exe':     row('control.exe',     ['T1218.002'], 'medium', 'Loads .CPL applet; arbitrary DLL with CPlApplet export'),

    // ── Printing (T1546) ─────────────────────────────────────────────────
    'printbrm.exe':    row('printbrm.exe',    ['T1218'], 'medium', 'Printer migration tool — arbitrary file copy via /b /f'),
  });
})();

const LolbasMap = Object.freeze({
  /**
   * Look up a single binary by name. Accepts a bare filename (`mshta.exe`),
   * a full path (`C:\Windows\System32\mshta.exe`), or just the stem
   * (`mshta`). Match is case-insensitive.
   * Returns the entry object or null.
   */
  lookup(name) {
    if (!name || typeof name !== 'string') return null;
    let s = name.trim().toLowerCase();
    // Strip surrounding quotes
    if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
      s = s.slice(1, -1);
    }
    // Strip path
    const slash = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'));
    if (slash >= 0) s = s.slice(slash + 1);
    if (LOLBAS_MAP[s]) return LOLBAS_MAP[s];
    // Bare-stem fallback — `mshta` → `mshta.exe`
    if (!s.endsWith('.exe') && LOLBAS_MAP[s + '.exe']) return LOLBAS_MAP[s + '.exe'];
    return null;
  },

  /**
   * Scan a free-form command line / text blob for any LOLBAS binary
   * mention. Returns a deduplicated array of entries (in first-mention
   * order). Duplicates within one input are collapsed — callers usually
   * want one detection per binary per artefact.
   *
   * Match grammar: word-boundary prefix; the binary literal; either
   * end-of-token (whitespace, quote, redirect, pipe, semicolon, EOF) or
   * `.exe` already in the literal. This avoids matching inside longer
   * identifiers (e.g. `wmic` won't match inside `wmicodes.dll`).
   */
  scan(text) {
    if (!text || typeof text !== 'string') return [];
    const lower = text.toLowerCase();
    const seen = new Set();
    const out = [];
    for (const key of Object.keys(LOLBAS_MAP)) {
      // Match `key` at word boundary; if key ends in .exe the boundary is
      // already strong, otherwise we additionally require a non-word char
      // (or EOF) after the stem. Stem-match falls back to scanning for
      // the .exe-less version too.
      const stem = key.endsWith('.exe') ? key.slice(0, -4) : key;
      // Built from a hard-coded LOLBAS_MAP key (string literal source);
      // the metachar replace below is belt-and-braces — no user input
      // ever reaches this regex source string.
      /* safeRegex: builtin */
      const re = new RegExp(`(?:^|[^a-z0-9_])${stem.replace(/[.\\+*?^$()[\]{}|]/g, '\\$&')}(?:\\.exe)?(?![a-z0-9_])`);
      if (re.test(lower) && !seen.has(key)) {
        seen.add(key);
        out.push(LOLBAS_MAP[key]);
      }
    }
    return out;
  },

  /**
   * Convenience: same as `scan` but returns the de-duplicated union of
   * ATT&CK technique IDs across all hits. Useful when a caller wants to
   * stamp a detection's `attack: [...]` field without iterating.
   */
  techniquesFor(text) {
    const techs = new Set();
    for (const e of LolbasMap.scan(text)) {
      for (const t of e.attack) techs.add(t);
    }
    return Array.from(techs);
  },
});

// Browser global — every Loupe module is loaded into one inline <script>
// at build time, so this assignment makes the helper visible everywhere.
if (typeof window !== 'undefined') window.LolbasMap = LolbasMap;
