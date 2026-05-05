'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-helpers.js — Timeline mode constants + pure helper functions.
//
// Split out of the legacy app-timeline.js monolith. Contains:
//   - All TIMELINE_* constants (keys, palette, presets, bucket options).
//   - All `_tl*` pure helper functions (timestamp parsing, auto-detect,
//     formatters, JSON path extraction, CSV cell escaping, etc.).
//
// No DOM, no class state — every function here is pure or returns scalar
// data. Loads BEFORE timeline-query.js (which uses _tlEsc, _tlMaybeJson,
// the regex tables, etc.) and BEFORE timeline-view.js (which uses
// everything).
//
// Analysis-bypass guard: this file does NOT import or call pushIOC,
// EncodedContentDetector, or any IOC plumbing. The Timeline route is
// intentionally analyser-free (see app-timeline-router.js header).
// ════════════════════════════════════════════════════════════════════════════

const TIMELINE_KEYS = Object.freeze({
  GRID_H: 'loupe_timeline_grid_h',
  CHART_H: 'loupe_timeline_chart_h',
  BUCKET: 'loupe_timeline_bucket',
  SECTIONS: 'loupe_timeline_sections',
  CARD_WIDTHS: 'loupe_timeline_card_widths',
  REGEX_EXTRACTS: 'loupe_timeline_regex_extracts',
  PIVOT: 'loupe_timeline_pivot',
  QUERY: 'loupe_timeline_query',
  QUERY_HISTORY: 'loupe_timeline_query_history',
  SUS_MARKS: 'loupe_timeline_sus_marks',
  CARD_ORDER: 'loupe_timeline_card_order',
  PINNED_COLS: 'loupe_timeline_pinned_cols',
  // Per-file grid column DISPLAY order — `{ [fileKey]: [colName, …] }`.
  // Persists the analyst's drag-reordered column arrangement across
  // reload. Stored as column NAMES (not real indices) because the real
  // index of any extracted column is unstable across the auto-extract
  // pass that runs ~100 ms post-load. On restore, names are resolved
  // back to live real indices via `this.columns.indexOf(name)`; any
  // name that no longer exists (column deleted, schema changed) is
  // silently dropped and the surviving order is healed by
  // `GridViewer._resolveColOrder`. Mirrors the `CARD_ORDER` shape.
  GRID_COL_ORDER: 'loupe_timeline_grid_col_order',
  // Per-file marker — `{ [fileKey]: true }` — set the first time the
  // best-effort auto-extract pass FIRES THE TOAST against a given file.
  // The auto-extract pass itself runs on every file open (it's
  // deterministic and fast), but the "Auto-extracted N fields" toast
  // would be noisy if it surfaced on every reopen, so we gate the
  // toast on this marker. Renamed (was `AUTOEXTRACT_DONE` /
  // `loupe_timeline_autoextract_done`) when the gating semantic
  // changed: previously it short-circuited the EXTRACTION itself,
  // which broke JSON-shaped CSVs because JSON-leaf columns aren't
  // persisted and so were silently lost on reopen. The legacy key is
  // deleted on first load by `_loadAutoExtractToastShownFor`. `_reset()`
  // wipes this via the `loupe_timeline_*` prefix. OWNED EXCLUSIVELY by
  // `_autoExtractBestEffort` — GeoIP enrichment has its own marker
  // (`GEOIP_DONE`).
  AUTOEXTRACT_TOAST_SHOWN: 'loupe_timeline_autoextract_toast_shown',
  // Legacy alias for the above key (pre-rename). Kept ONLY so the
  // migration path in `_loadAutoExtractToastShownFor` can locate and
  // delete stale entries from existing browser profiles. Do not write
  // to this key — it has no consumers post-rename.
  AUTOEXTRACT_DONE_LEGACY: 'loupe_timeline_autoextract_done',
  // Per-file marker — `{ [fileKey]: true }` — set the first time GeoIP
  // enrichment runs against a given file, so deleted geo / asn columns
  // stay deleted on reopen. Independent from `AUTOEXTRACT_DONE` so that
  // a file with no IPv4-shaped columns (the GeoIP no-op path stamps this
  // marker too, to avoid re-running the IP-detect scan on every reopen)
  // doesn't inadvertently disable JSON / URL / host extraction.
  // `_reset()` wipes this via the `loupe_timeline_*` prefix.
  GEOIP_DONE: 'loupe_timeline_geoip_done',
  // Entities-section parity with Top values (per-file persistence). The
  // entity card head was promoted from a fixed type-label to a Top-values-
  // style head with pin / copy / sort-cycle / search affordances; these
  // two keys persist the per-file pinned-types ordering and the analyst's
  // chosen group order, mirroring `PINNED_COLS` / `CARD_ORDER` semantics.
  ENT_PINNED: 'loupe_timeline_entity_pinned',
  ENT_ORDER: 'loupe_timeline_entity_order',
  // ATT&CK group-by toggle for the Detections section. Boolean stored
  // globally (not per-file) — analysts who turn it on once typically want
  // it on for every EVTX they open.
  DETECTIONS_GROUP: 'loupe_timeline_detections_group',
});


// Hard row cap.
const TIMELINE_MAX_ROWS = RENDER_LIMITS.MAX_TIMELINE_ROWS;

// File extensions that always open in the Timeline view.
//
// `.log` is treated as a first-class space-delimited tabular format
// (Apache / Nginx access logs in Common / Combined Log Format). The
// router passes `kindHint: 'log'` and `explicitDelim: ' '` through to
// the CSV parse path so the bracketed `[DD/Mon/YYYY:HH:MM:SS ±ZZZZ]`
// timestamp can be re-merged across the embedded space, and so the
// canonical CLF column names (ip / ident / auth / time / request /
// status / bytes / referer / user_agent) are applied when the row
// width matches. Files without a `.log` extension can still be
// detected via `_sniffTimelineContent` (see timeline-router.js).
//
// `.jsonl` and `.ndjson` are the canonical JSONL extensions. They
// route into the structured-log JSONL parser (kindHint: 'jsonl');
// extensionless / mis-named JSONL files are caught by the JSONL
// probe in `_sniffTimelineContent`.
const TIMELINE_EXTS = new Set(['csv', 'tsv', 'evtx', 'sqlite', 'db', 'log',
                               'jsonl', 'ndjson', 'cef', 'leef',
                               'pcap', 'pcapng', 'cap']);

// ── CLF (Common / Combined Log Format) helpers ─────────────────────────────
// Apache / Nginx access logs use a bracketed date token containing a
// single space: `[20/Jun/2012:19:05:12 +0200]`. A naive single-space
// CSV split chops it into two cells — the open bracket + date and the
// timezone + close bracket — so we re-merge them post-parse before
// `_tlAutoDetectTimestampCol` and `_tlParseTimestamp` see the row.
// The merge is invoked only on the `.log` parse path (and on
// extensionless files the CLF sniffer matches), never on plain
// CSV / TSV — so even a freak false positive can't reach unrelated
// files.
// `_tlTokenizeClfLine(line)` — dedicated parser for one Apache / Nginx
// Common (or Combined) Log Format physical line. Returns an array of
// cells (length 7 = common, 9 = combined) or `null` for any line whose
// shape doesn't match.
//
// Why a custom tokeniser rather than reusing `CsvRenderer.parseChunk`
// with `delim=' '`: CLF uses **backslash-escaped quotes** (`\"`) inside
// quoted fields, not RFC4180-style doubled quotes (`""`). Roughly 6 %
// of real Apache logs contain `\"` (think User-Agent strings that
// quote a sub-token); RFC4180 sees `\"` as `\` then end-of-quoted-cell
// and the parser then loses synchronisation for the rest of the file
// — every subsequent line gets glued onto a single mega-cell. A
// fixed-shape lexer is the only correct answer.
//
// CLF shape, combined:
//   %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"
//   = 3 unquoted, 1 bracketed `[…]`, 1 quoted, 2 unquoted, 2 quoted
//
// CLF shape, common (CLF proper, no Combined):
//   %h %l %u %t \"%r\" %>s %b
//   = 3 unquoted, 1 bracketed, 1 quoted, 2 unquoted
//
// Whitespace inside quoted / bracketed runs is preserved verbatim.
// Backslash escapes are decoded: `\"` → `"`, `\\` → `\`. Other
// `\X` are passed through as `\X` (Apache itself doesn't define
// further escapes; passing-through is closer to mod_log_config's
// actual behaviour than silently dropping the backslash).
function _tlTokenizeClfLine(line) {
  if (!line) return null;
  const len = line.length;
  let i = 0;
  // Skip leading spaces (rare but harmless).
  while (i < len && line.charCodeAt(i) === 0x20) i++;
  if (i >= len) return null;
  const out = [];

  // Reads a run of non-space characters, advances `i` past the
  // trailing space (or to EOL). Returns the captured text.
  const readUnquoted = () => {
    const start = i;
    while (i < len && line.charCodeAt(i) !== 0x20) i++;
    const tok = line.slice(start, i);
    while (i < len && line.charCodeAt(i) === 0x20) i++;
    return tok;
  };

  // Reads `[…]`. Caller has already verified `line[i] === '['`. The
  // closing `]` is matched literally — bracketed dates contain no
  // nested brackets, so we don't need backslash handling here.
  const readBracketed = () => {
    const start = i;                       // include the `[`
    i++;                                   // step past `[`
    while (i < len && line.charCodeAt(i) !== 0x5D /* ] */) i++;
    if (i >= len) return null;             // unterminated → caller bails
    i++;                                   // step past `]`
    const tok = line.slice(start, i);
    while (i < len && line.charCodeAt(i) === 0x20) i++;
    return tok;
  };

  // Reads `"…"` with `\\` / `\"` decoded. Caller has already verified
  // `line[i] === '"'`. The closing `"` is the first un-escaped `"` we
  // see. Returns the inner text (quotes stripped, escapes decoded).
  const readQuoted = () => {
    i++;                                   // step past opening `"`
    let result = '';
    let runStart = i;
    while (i < len) {
      const c = line.charCodeAt(i);
      if (c === 0x5C /* \\ */ && i + 1 < len) {
        const next = line.charCodeAt(i + 1);
        // Decode `\\` and `\"`; pass other `\X` through unchanged.
        if (next === 0x22 /* " */ || next === 0x5C) {
          if (i > runStart) result += line.slice(runStart, i);
          result += String.fromCharCode(next);
          i += 2;
          runStart = i;
          continue;
        }
        i += 2;                            // skip the pair, leave runStart
        continue;
      }
      if (c === 0x22 /* " */) {
        if (i > runStart) result += line.slice(runStart, i);
        i++;                               // step past closing `"`
        while (i < len && line.charCodeAt(i) === 0x20) i++;
        return result;
      }
      i++;
    }
    return null;                           // unterminated → caller bails
  };

  // 1. host (`%h`)        — unquoted
  out.push(readUnquoted());
  if (i >= len) return null;
  // 2. ident (`%l`)       — unquoted (`-` if absent)
  out.push(readUnquoted());
  if (i >= len) return null;
  // 3. authuser (`%u`)    — unquoted (`-` if absent)
  out.push(readUnquoted());
  if (i >= len) return null;
  // 4. time (`%t`)        — bracketed `[20/Jun/2012:19:05:12 +0200]`
  if (line.charCodeAt(i) !== 0x5B /* [ */) return null;
  const time = readBracketed();
  if (time === null) return null;
  out.push(time);
  if (i >= len) return null;
  // 5. request (`\"%r\"`) — quoted
  if (line.charCodeAt(i) !== 0x22 /* " */) return null;
  const request = readQuoted();
  if (request === null) return null;
  out.push(request);
  if (i >= len) return null;
  // 6. status (`%>s`)     — unquoted
  out.push(readUnquoted());
  // 7. bytes (`%b`)       — unquoted (last common-format field)
  if (i >= len) {
    // Common Log Format — return 7 cells if we got here cleanly.
    // (`%b` was consumed by readUnquoted on field 6 above? No — it
    // wasn't, fall through.) But the standard ordering is fields
    // 6 = status, 7 = bytes. If `i` ran out *before* field 7, the
    // line is malformed.
    return null;
  }
  out.push(readUnquoted());
  // CLF Common stops here. CLF Combined adds two more quoted fields.
  if (i >= len) return out;                // 7 cells — Common
  // 8. referer            — quoted
  if (line.charCodeAt(i) === 0x22 /* " */) {
    const referer = readQuoted();
    if (referer === null) return out;      // unterminated tail — keep 7
    out.push(referer);
  } else {
    return out;                            // unexpected — keep 7
  }
  if (i >= len) return out;                // some logs omit user-agent
  // 9. user-agent         — quoted
  if (line.charCodeAt(i) === 0x22 /* " */) {
    const ua = readQuoted();
    if (ua === null) return out;
    out.push(ua);
  }
  return out;                              // 9 cells — Combined
}

// ── Syslog (RFC 3164 + 5424) helpers ──────────────────────────────────────
//
// Both RFCs lead with a `<PRI>` token that encodes severity (low 3 bits)
// and facility (upper bits) as a single integer 0..191. Every other
// shape detail differs:
//
//   RFC 3164 (BSD syslog, the de-facto Cisco/network-appliance format):
//     <PRI>MMM DD HH:MM:SS host program[pid]: message
//   RFC 5424 (the modern replacement, well-defined ISO timestamp):
//     <PRI>VERSION ISOTIMESTAMP HOSTNAME APP PROCID MSGID [SD-PARAMS] MSG
//
// The PRI integer is identical in both RFCs and shared via
// `_tlDecodePri`. `_tlSyslogSeverityName` maps the 0..7 severity to its
// canonical lowercase name (`emergency` … `debug`). `_tlSyslogFacilityName`
// maps 0..23 to the named facilities Cisco/Linux use.
//
// RFC 3164 timestamps lack a year. `_tlInferYear(fileLastModified)`
// returns the year to assume; if a parsed timestamp would be > 30 days
// in the future relative to the inferred year, the parser silently
// rolls back one year (the same heuristic rsyslog and journalctl use).

const _TL_SYSLOG_SEVERITY = ['emergency', 'alert', 'critical', 'error',
                             'warning', 'notice', 'informational', 'debug'];
const _TL_SYSLOG_FACILITY = [
  'kern', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news',
  'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'audit', 'alert', 'clock',
  'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7',
];

function _tlSyslogSeverityName(sev) {
  return _TL_SYSLOG_SEVERITY[sev | 0] || '';
}
function _tlSyslogFacilityName(fac) {
  return _TL_SYSLOG_FACILITY[fac | 0] || ('facility' + (fac | 0));
}
// Decode an RFC 3164/5424 priority integer. Returns
// `{ facility, severity, severityName, facilityName }` or `null` for
// out-of-range / non-integer inputs.
function _tlDecodePri(pri) {
  // Tolerate string PRIs (the line tokeniser hands us a captured
  // regex group, which is a string), but reject `null` / `undefined` /
  // `''` outright — the coercion `+null === 0` would otherwise return
  // a "valid" kern.emerg result for a missing PRI which is
  // misleading. Bare numbers and parseable digit strings pass.
  if (pri === null || pri === undefined || pri === '') return null;
  const n = +pri;
  if (!Number.isInteger(n) || n < 0 || n > 191) return null;
  const severity = n & 0x07;
  const facility = (n >> 3) & 0x1F;
  return {
    facility,
    severity,
    severityName: _tlSyslogSeverityName(severity),
    facilityName: _tlSyslogFacilityName(facility),
  };
}

// Three-letter month abbreviation → 0-indexed month.
const _TL_MONTH_ABBR = {
  jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5,
  jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11,
};

// Infer the year to assume for RFC 3164 timestamps (which lack a year).
// Uses `file.lastModified` when available, otherwise the current year.
// Deterministic per-file: identical bytes + identical lastModified
// always produce identical output, satisfying the build determinism rule
// for any code path the parser reaches. (The fallback to "current year"
// only fires for File objects without lastModified — synthetic test
// inputs — where determinism within a single run is sufficient.)
function _tlInferYear(fileLastModified) {
  if (Number.isFinite(fileLastModified) && fileLastModified > 0) {
    return new Date(fileLastModified).getUTCFullYear();
  }
  return new Date().getUTCFullYear();
}

// Tokenise one RFC 3164 syslog line. Shape:
//   <PRI>MMM DD HH:MM:SS host program[pid]: message
// `host`, `program`, `pid` are all optional in practice (some senders
// omit the program; some embed only `program:` without a PID; some
// omit the trailing colon entirely). The tokeniser is intentionally
// forgiving — it returns whatever it can extract and always emits a
// 7-cell row matching `_TL_SYSLOG3164_COLS`.
//
// `assumedYear` is the year the timestamp should land in (see
// `_tlInferYear`). Tokens with no parseable timestamp leave
// the timestamp cell empty; downstream `_tlParseTimestamp` will then
// just see '' and the row falls outside any time-bucket. The host /
// program / pid cells fall through unchanged on parse failures so the
// raw text is still searchable in the grid.
//
// Returns `null` for inputs that don't begin with `<PRI>` — the caller
// is expected to skip those lines (continuation lines for multi-line
// events, garbage interleaved into the file, etc.).
function _tlTokenizeSyslog3164(line, fileLastModifiedMs) {
  if (!line) return null;
  const m = /^<(\d{1,3})>/.exec(line);
  if (!m) return null;
  const pri = +m[1];
  if (pri < 0 || pri > 191) return null;
  let i = m[0].length;
  while (i < line.length && line.charCodeAt(i) === 0x20) i++;
  const ts = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+/.exec(line.slice(i));
  let timestamp = '';
  // Year-inference rule. RFC 3164 timestamps omit the year. We use the
  // file's last-modified time ("now" relative to the file) as the
  // upper bound: log entries should be at-or-before mtime. Try the
  // file's mtime year first; if the resulting ms lands more than 30
  // days past mtime it's almost certainly from the previous year.
  // The 30-day buffer absorbs clock-skew + timezone offset (mtime is
  // typically local-tz; the log line carries no timezone). When mtime
  // is 0/missing we fall back to the current UTC year — non-
  // deterministic across runs but the only sensible choice without
  // an mtime to anchor to.
  const nowMs = (Number.isFinite(fileLastModifiedMs) && fileLastModifiedMs > 0)
    ? fileLastModifiedMs : Date.now();
  const assumedYear = new Date(nowMs).getUTCFullYear();
  if (ts) {
    const mo = _TL_MONTH_ABBR[ts[1].toLowerCase()];
    const d  = +ts[2];
    const hh = +ts[3], mm = +ts[4], ss = +ts[5];
    if (mo !== undefined && d >= 1 && d <= 31
        && hh < 24 && mm < 60 && ss < 60) {
      let yr = assumedYear | 0;
      let candidateMs = Date.UTC(yr, mo, d, hh, mm, ss);
      if (candidateMs > nowMs + 30 * 86400_000) {
        yr -= 1;
        candidateMs = Date.UTC(yr, mo, d, hh, mm, ss);
      }
      // Emit as ISO-ish "YYYY-MM-DD HH:MM:SS" (no Z) — matches the
      // EVTX timestamp shape that `_tlParseTimestamp` already
      // recognises via the ISO branch.
      const pad = n => String(n).padStart(2, '0');
      timestamp = `${yr}-${pad(mo + 1)}-${pad(d)} ${pad(hh)}:${pad(mm)}:${pad(ss)}`;
    }
    i += ts[0].length;
  }
  // After the timestamp, the rest is "HEADER MSG" where HEADER is
  // optionally `host program[pid]:` (the colon ends HEADER). We split
  // on the first colon — but carefully: a colon inside a host name is
  // legal (IPv6) and a colon inside the message body is common.
  // The RFC 3164 grammar says: host is a single token (no spaces)
  // followed by a space, then TAG (a-zA-Z0-9 only) up to 32 chars,
  // optionally followed by `[pid]`, then `:` then a single space, then
  // CONTENT. We honour that grammar but tolerate missing pieces.
  let host = '', program = '', pid = '', message = '';
  const rest = line.slice(i);
  // Find host (first whitespace-bounded token). Empty if rest doesn't
  // start with a printable token — rare, but tolerate.
  const hostM = /^(\S+)\s+(.*)$/.exec(rest);
  if (hostM) {
    host = hostM[1];
    let after = hostM[2];
    // TAG: up to 32 alnum + `_/-.` chars, optional `[pid]`, then `:` + space.
    // We accept any program-like token before the first colon as long
    // as it doesn't contain whitespace before the colon.
    const tagM = /^([A-Za-z0-9_./\-]{1,64})(?:\[(\d{1,10})\])?:\s*(.*)$/.exec(after);
    if (tagM) {
      program = tagM[1];
      pid = tagM[2] || '';
      message = tagM[3];
    } else {
      message = after;
    }
  } else {
    message = rest;
  }
  const decoded = _tlDecodePri(pri);
  return [
    timestamp,
    decoded ? decoded.severityName : '',
    decoded ? decoded.facilityName : '',
    host,
    program,
    pid,
    message,
  ];
}

// Canonical column order for RFC 3164 syslog. `Timestamp` lives at
// index 0 so `_tlAutoDetectTimestampCol`'s header-hint regex picks it
// up; `Severity` at index 1 makes it the default stack column via
// `_tlAutoDetectStackCol` (it's in the `_TL_STACK_EXACT` whitelist).
const _TL_SYSLOG3164_COLS = ['Timestamp', 'Severity', 'Facility', 'Host',
                             'Program', 'PID', 'Message'];

// Tokenise one RFC 5424 syslog line. Shape:
//   <PRI>VER TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
// where any field except PRI/VER may be `-` (NILVALUE). TIMESTAMP is
// ISO 8601 with optional fractional seconds + tz offset, HOSTNAME etc
// are non-whitespace tokens (or `-`), SD is `-` or a sequence of
// `[ID k="v" k="v"]` blocks back-to-back (no separator between
// blocks), and MSG is everything after SD — optionally prefixed with
// a UTF-8 BOM (`\xEF\xBB\xBF`).
//
// The tokeniser is forgiving: it accepts NILVALUEs, missing trailing
// fields (rare but seen in mis-implementations), and SD blocks
// containing escaped `\"`, `\\`, `\]`. It always emits a 9-cell row
// matching `_TL_SYSLOG5424_COLS`. Returns `null` for inputs that
// don't begin with the `<PRI>VER` digit-prefixed shape — the caller
// is expected to skip those (continuation lines, garbage, etc.).
//
// `fileLastModifiedMs` is plumbed in for symmetry with the 3164
// tokeniser but is not used: 5424 timestamps already carry an explicit
// year, so no inference is needed. We accept the param to keep the
// `STRUCTURED_LOG_KINDS` registry signature uniform.
function _tlTokenizeSyslog5424(line, _fileLastModifiedMs) {
  if (!line) return null;
  // Strip an optional leading UTF-8 BOM in case the line itself starts
  // with one (rsyslog under certain configs prepends one to every line
  // rather than just the MSG body).
  if (line.charCodeAt(0) === 0xFEFF) line = line.slice(1);
  // PRI + VERSION: `<NNN>V`. RFC 5424 currently mandates VERSION=1 but
  // we accept any 1-2 digit version to avoid false negatives if the
  // standard ever revs. The space after VERSION is mandatory.
  const m = /^<(\d{1,3})>(\d{1,2})\s/.exec(line);
  if (!m) return null;
  const pri = +m[1];
  if (pri < 0 || pri > 191) return null;
  let i = m[0].length;

  // Helper: read the next whitespace-delimited token starting at `i`.
  // Returns { token, end } where `end` is the index of the trailing
  // space (or line.length). Skips one trailing space. NILVALUE `-`
  // becomes ''.
  const nextToken = () => {
    if (i >= line.length) return '';
    const sp = line.indexOf(' ', i);
    const tok = sp === -1 ? line.slice(i) : line.slice(i, sp);
    i = sp === -1 ? line.length : sp + 1;
    return tok === '-' ? '' : tok;
  };

  const timestamp = nextToken();
  const host      = nextToken();
  const app       = nextToken();
  const procid    = nextToken();
  const msgid     = nextToken();

  // STRUCTURED-DATA: either NILVALUE `-` followed by space+MSG, or a
  // sequence of `[...]` blocks back-to-back. Within a quoted value
  // (`"..."`) the chars `\"`, `\\`, `\]` are escaped. We walk the
  // string in a tiny state machine to find the end of SD, then
  // everything after a single trailing space is MSG.
  let sd = '';
  if (i < line.length) {
    if (line.charCodeAt(i) === 0x2D /* '-' */) {
      // NILVALUE SD. Eat the dash + optional trailing space; rest is MSG.
      i += 1;
      if (i < line.length && line.charCodeAt(i) === 0x20) i += 1;
      sd = '';
    } else if (line.charCodeAt(i) === 0x5B /* '[' */) {
      const sdStart = i;
      // Walk back-to-back `[...]` blocks. Inside a block, track
      // whether we're inside a quoted PARAM-VALUE so a `]` inside a
      // quote doesn't terminate the block prematurely. Backslash is
      // only a literal escape inside quoted values per RFC 5424
      // § 6.3.3.
      while (i < line.length && line.charCodeAt(i) === 0x5B) {
        i += 1;          // consume '['
        let inQuote = false;
        while (i < line.length) {
          const c = line.charCodeAt(i);
          if (inQuote) {
            if (c === 0x5C /* '\' */ && i + 1 < line.length) {
              // Escaped char inside a quoted PARAM-VALUE.
              i += 2;
              continue;
            }
            if (c === 0x22 /* '"' */) inQuote = false;
            i += 1;
            continue;
          }
          if (c === 0x22 /* '"' */) { inQuote = true; i += 1; continue; }
          if (c === 0x5D /* ']' */) { i += 1; break; }
          i += 1;
        }
      }
      sd = line.slice(sdStart, i);
      // Eat the optional single space between SD and MSG.
      if (i < line.length && line.charCodeAt(i) === 0x20) i += 1;
    }
    // Any other shape (truncated record, garbage in SD slot) leaves
    // `sd = ''` and treats the rest as MSG.
  }

  // MSG. Strip a leading UTF-8 BOM if the producer included one.
  let msg = line.slice(i);
  if (msg.charCodeAt(0) === 0xFEFF) msg = msg.slice(1);

  const decoded = _tlDecodePri(pri);
  return [
    timestamp,
    decoded ? decoded.severityName : '',
    decoded ? decoded.facilityName : '',
    host,
    app,
    procid,
    msgid,
    sd,
    msg,
  ];
}

// Canonical column order for RFC 5424 syslog. `Timestamp` at index 0
// (header-hint regex picks it up); `Severity` at index 1 (default
// stack column).
const _TL_SYSLOG5424_COLS = ['Timestamp', 'Severity', 'Facility', 'Host',
                             'App', 'ProcID', 'MsgID', 'StructuredData',
                             'Message'];

// ── Zeek TSV tokeniser (stateful) ─────────────────────────────────
// Zeek (formerly Bro) emits one log file per protocol/path
// (`conn.log`, `dns.log`, `http.log`, `ssl.log`, …). Each file is
// tab-separated with a 7-line `#`-prefixed header preamble:
//
//   #separator \x09
//   #set_separator	,
//   #empty_field	(empty)
//   #unset_field	-
//   #path	conn
//   #open	2024-10-15-12-00-00
//   #fields	ts	uid	id.orig_h	id.orig_p	...
//   #types	time	string	addr	port	...
//   <tab-separated data rows>
//   #close	2024-10-15-13-00-00
//
// `ts` is a unix-epoch float ('1697371200.123456'). `-` and
// `(empty)` are the sentinel NILVALUE strings (configurable via
// `#unset_field` / `#empty_field` but in practice always those
// defaults). The schema (column count) varies by `#path` — `conn.log`
// has 21 fields, `dns.log` has 23, `http.log` has 28, etc. — so the
// tokeniser MUST read the column list from the file's own `#fields`
// header rather than hard-coding it.
//
// `_tlMakeZeekTokenizer()` returns `{tokenize, getColumns,
// getDefaultStackColIdx, getFormatLabel}` closing over per-parse
// state. The factory pattern ensures state can't leak between
// files when the worker is reused.
//
// Default histogram stack column is chosen heuristically per `#path`:
//   conn → 'proto' (TCP / UDP / ICMP)
//   dns  → 'qtype_name' (A / AAAA / TXT / …)
//   http → 'method'    (GET / POST / …)
//   ssl  → 'version'   (TLSv1.2 / TLSv1.3 / …)
//   else → col 1 (the auto-detect fallback)
const _TL_ZEEK_STACK_BY_PATH = {
  conn:  'proto',
  dns:   'qtype_name',
  http:  'method',
  ssl:   'version',
  weird: 'name',
  files: 'mime_type',
  notice: 'note',
};
// ── JSONL tokeniser (stateful, schema from first record) ──────────
// Newline-delimited JSON (`.jsonl`, `.ndjson`, `.json`-as-stream) is
// pervasive in modern log pipelines: AWS CloudTrail (one JSON
// object per line), Kubernetes container logs, fluentd / vector /
// Loki sinks, application structured logging, etc. Each line parses
// to a JSON object; the tokeniser flattens it to a dotted-path cell
// matrix.
//
// Design choices:
//   - Schema is fixed after the first record. New keys in later
//     records are JSON-encoded into a single `_extra` column so the
//     data isn't lost; missing keys leave their cell empty. This
//     keeps the column count stable through the worker's
//     `_postColumns` early-emit pathway.
//   - Nesting is flattened by dotted path (`user.name`, `request.path`).
//     Arrays are JSON-encoded in-place — flattening them by index
//     would explode the column count for variable-length lists.
//   - Primitive null / undefined / boolean values render as their
//     literal string form ('null', 'true', '1234'); strings render
//     verbatim.
//
// The tokeniser uses a stateful factory matching the Zeek shape so
// the existing structured-log loop in the worker + sync fallback
// can dispatch to it without further plumbing changes.
//
// Depth cap: nested-object flattening stops at depth 8 to bound
// pathological inputs. Anything deeper is JSON-encoded as the
// 8th-level cell value.
const _TL_JSONL_FLATTEN_MAX_DEPTH = 8;
const _TL_JSONL_MAX_COLUMNS = 256;
function _tlMakeJsonlTokenizer() {
  // `schema` is the dotted-path key list resolved from the first
  // record. `_extra` is ALWAYS appended to the column list (even
  // when no row needs it) so the worker's `_postColumns` early-emit
  // can fix the column count up front — adding `_extra` mid-stream
  // would violate the fixed-width row contract. Empty cells in
  // `_extra` are the common case; rows with unknown keys spill
  // their JSON-encoded extras into that slot.
  let schema = null;          // string[] | null — set on first record
  let schemaIndex = null;     // Map<string, number>

  // Recursively walk an object, emitting `path -> stringValue` pairs
  // into the `out` map. Arrays + non-plain objects are JSON-encoded
  // verbatim.
  const flatten = (val, path, out, depth) => {
    if (val === null || val === undefined) {
      if (path) out[path] = val === null ? 'null' : '';
      return;
    }
    const t = typeof val;
    if (t === 'string') { out[path] = val; return; }
    if (t === 'number' || t === 'boolean' || t === 'bigint') {
      out[path] = String(val); return;
    }
    if (Array.isArray(val) || depth >= _TL_JSONL_FLATTEN_MAX_DEPTH) {
      try { out[path] = JSON.stringify(val); }
      catch (_) { out[path] = String(val); }
      return;
    }
    if (t !== 'object') { out[path] = String(val); return; }
    // Plain-ish object — recurse with dotted path.
    const keys = Object.keys(val);
    if (!keys.length && path) {
      out[path] = '{}';
      return;
    }
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i];
      flatten(val[k], path ? path + '.' + k : k, out, depth + 1);
    }
  };

  const tokenize = (line, _mtime) => {
    if (!line) return null;
    // Tolerate a leading BOM on the very first line and any
    // surrounding whitespace.
    let s = line;
    if (s.charCodeAt(0) === 0xFEFF) s = s.slice(1);
    s = s.trim();
    if (!s || s.charCodeAt(0) !== 0x7B /* '{' */) return null;
    let obj;
    try { obj = JSON.parse(s); }
    catch (_) { return null; }
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null;
    const flat = Object.create(null);
    flatten(obj, '', flat, 0);
    if (!schema) {
      // First valid record. Keys observed here become the canonical
      // schema. Cap to MAX_COLUMNS to avoid OOM on extreme records.
      schema = Object.keys(flat).slice(0, _TL_JSONL_MAX_COLUMNS);
      schemaIndex = Object.create(null);
      for (let i = 0; i < schema.length; i++) schemaIndex[schema[i]] = i;
    }
    // Project this record onto the schema; collect any unknown keys
    // into the `_extra` slot. `cells` is sized `schema.length + 1`
    // (one slot for `_extra`, always present) so width matches the
    // column list returned by `getColumns()`.
    const cells = new Array(schema.length + 1).fill('');
    let extras = null;
    const keys = Object.keys(flat);
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i];
      const idx = schemaIndex[k];
      if (idx !== undefined) {
        cells[idx] = flat[k];
      } else {
        if (!extras) extras = Object.create(null);
        extras[k] = flat[k];
      }
    }
    if (extras) {
      try { cells[schema.length] = JSON.stringify(extras); }
      catch (_) { cells[schema.length] = ''; }
    }
    return cells;
  };

  // Called by the structured-log loop on the first valid data row.
  // `schema` was populated inside `tokenize` (each JSON record
  // carries its own keys), so `width` is ignored. `_extra` is always
  // appended so the column count is fixed for the lifetime of the
  // parse.
  const getColumns = (_width) => {
    const cols = schema ? schema.slice() : [];
    cols.push('_extra');
    return cols;
  };

  // Stack-by selection: prefer well-known categorical fields, in
  // priority order. Each candidate that exists in the schema beats
  // the auto-detect default (col 1). Returning `null` defers to the
  // host-side cardinality probe.
  const _STACK_CANDIDATES = [
    'level', 'severity', 'log.level', 'eventName', 'event_type',
    'eventType', 'action', 'method', 'status', 'category',
  ];
  const getDefaultStackColIdx = () => {
    if (!schema) return null;
    for (let i = 0; i < _STACK_CANDIDATES.length; i++) {
      const idx = schemaIndex[_STACK_CANDIDATES[i]];
      if (idx !== undefined) return idx;
    }
    return null;
  };

  const getFormatLabel = () => 'JSONL';

  return { tokenize, getColumns, getDefaultStackColIdx, getFormatLabel };
}

// ── AWS CloudTrail tokeniser (JSONL with canonical projection) ────
// AWS CloudTrail emits one of two shapes:
//   • Wrapped:  `{"Records":[{event}, {event}, ...]}` — single JSON
//     document. The router unwraps this into a JSONL byte stream
//     before dispatch (`Records[i]` → one line each).
//   • JSONL:    one event per line, no wrapper. The router sniffs
//     this directly via the JSONL probe + a CloudTrail-key gate
//     (presence of `eventName` and `eventTime` in ≥1 of the first
//     5 records).
//
// Both routes converge on this tokeniser, which is a thin wrapper
// over `_tlMakeJsonlTokenizer`:
//   • Pre-seeds the schema with the CloudTrail canonical column
//     order so the most useful columns (Time · Name · Source ·
//     Region · IP · User) appear left-aligned regardless of the
//     order they happen to occur in the first record.
//   • Overrides the default stack column to `eventName` (rather
//     than the generic JSONL priority list).
//   • Labels the view `AWS CloudTrail`.
//
// Unknown keys still spill into `_extra`; events missing canonical
// keys leave their cell blank — the schema width is fixed.
const _TL_CLOUDTRAIL_CANONICAL_COLS = [
  'eventTime', 'eventName', 'eventSource', 'awsRegion',
  'sourceIPAddress', 'userIdentity.type', 'userIdentity.userName',
  'userIdentity.arn', 'userIdentity.accountId', 'userAgent',
  'eventID', 'eventType', 'recipientAccountId', 'requestID',
  'errorCode', 'errorMessage', 'readOnly', 'managementEvent',
];
function _tlMakeCloudTrailTokenizer() {
  // Build a JSONL tokeniser, but pre-seed the schema by feeding a
  // synthetic record with all canonical keys present. After the
  // first real record, any keys it carries that aren't in the
  // canonical list will spill to `_extra` — that's intentional:
  // CloudTrail records have ~30-50 keys, most of them service-
  // specific `requestParameters.*` / `responseElements.*` blobs
  // that don't belong in the headline grid.
  //
  // To pre-seed without losing real data, we manually populate the
  // JSONL helper's `schema`/`schemaIndex` via a controlled first
  // call. Easiest path: synthesise a record with every canonical
  // key and feed it through `tokenize`, then DISCARD that row by
  // returning `null` to the caller. The schema persists for the
  // lifetime of the closure.
  const inner = _tlMakeJsonlTokenizer();
  // Pre-seed the schema. Build a JSON line with canonical keys —
  // the inner tokeniser will resolve them in order on its first
  // call. Use empty-string values; they survive the JSONL
  // flattener (strings render verbatim) and lock the schema.
  const seed = {};
  for (let i = 0; i < _TL_CLOUDTRAIL_CANONICAL_COLS.length; i++) {
    // Nested keys (`userIdentity.type`) need to be reified as an
    // actual nested object so the JSONL flattener emits the
    // dotted-path key. Walk the dotted segments and build the
    // tree.
    const path = _TL_CLOUDTRAIL_CANONICAL_COLS[i].split('.');
    let cur = seed;
    for (let j = 0; j < path.length - 1; j++) {
      const seg = path[j];
      if (!cur[seg] || typeof cur[seg] !== 'object') cur[seg] = {};
      cur = cur[seg];
    }
    cur[path[path.length - 1]] = '';
  }
  inner.tokenize(JSON.stringify(seed), 0);

  return {
    tokenize: (line, mtime) => inner.tokenize(line, mtime),
    getColumns: (width) => inner.getColumns(width),
    getDefaultStackColIdx: () => {
      // Always stack on `eventName` for CloudTrail. It's the second
      // canonical column (index 1).
      return _TL_CLOUDTRAIL_CANONICAL_COLS.indexOf('eventName');
    },
    getFormatLabel: () => 'AWS CloudTrail',
  };
}

// ── CEF (Common Event Format — ArcSight) tokeniser ────────────────
// CEF is the lingua franca of SIEM appliances: ArcSight, Splunk
// HTTP-event-collector inputs, McAfee ESM, Imperva, Palo Alto,
// Check Point, Fortinet, Juniper SRX, Trend Micro, F5 ASM, Cisco
// firewalls, etc. Lines look like:
//
//   CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|ext
//
// where the first 7 fields are pipe-delimited and the trailing
// `ext` is a space-separated `key=value` extension block. The line
// is OPTIONALLY prefixed by a syslog header (RFC 3164 or 5424) —
// real-world deployments overwhelmingly tunnel CEF over syslog —
// so the tokeniser strips any text before the literal `CEF:0|`.
//
// Escaping rules (RFC-CEF Section 4.4):
//   • In header fields  : `\|`, `\\`
//   • In ext values     : `\=`, `\\`, `\n` (newline), `\r` (CR)
// Keys never contain spaces or `=`.
//
// Schema:
//   • 7 fixed header columns: Version, Vendor, Product, Version2,
//     SignatureID, Name, Severity. (`Version2` distinguishes the
//     pipe-3 product-version field from the leading `CEF:0` -
//     parsed-out-as `Version` - protocol version.)
//   • Dynamic extension keys, locked from the first record's
//     extension block (capped at MAX_COLUMNS - 7).
//   • One trailing `_extra` column for keys not in the locked set
//     (later records carrying new keys spill there as JSON).
//
// Histogram stack column: `Severity` (always present). CEF severity
// is 0–10 (low → high) plus the legacy text values
// `Unknown / Low / Medium / High / Very-High`; either form renders
// fine as a categorical.
const _TL_CEF_HEADER_COLS = [
  'Version', 'Vendor', 'Product', 'ProductVersion',
  'SignatureID', 'Name', 'Severity',
];
const _TL_CEF_MAX_EXT_COLUMNS = 256;
function _tlMakeCEFTokenizer() {
  // Extension schema is locked from the first valid record.
  let extSchema = null;            // string[] | null
  let extSchemaIndex = null;       // {key:string -> idx:number}

  // Split a CEF line into [headerFields, extString]. Returns null
  // for non-CEF input. Strips any leading syslog wrapper.
  const splitHeader = (line) => {
    if (!line) return null;
    // Find the literal `CEF:` token (CEF version is always 0; we
    // accept 0 or 1 to match the spec). Anything before it is a
    // syslog wrapper and is discarded.
    const cefIdx = line.indexOf('CEF:');
    if (cefIdx < 0) return null;
    const cefBody = line.slice(cefIdx);
    // Walk the cefBody splitting on unescaped `|`. The 7 header
    // fields end at the 7th `|`; everything after is the ext.
    const fields = [];
    let cur = '';
    let i = 0;
    const n = cefBody.length;
    while (i < n && fields.length < 7) {
      const ch = cefBody.charCodeAt(i);
      if (ch === 0x5C /* \ */ && i + 1 < n) {
        // Backslash-escape: copy the next char verbatim.
        cur += cefBody.charAt(i + 1);
        i += 2;
        continue;
      }
      if (ch === 0x7C /* | */) {
        fields.push(cur);
        cur = '';
        i++;
        continue;
      }
      cur += cefBody.charAt(i);
      i++;
    }
    if (fields.length < 7) return null;   // malformed
    // The first field is `CEF:N` — strip the `CEF:` prefix so the
    // cell renders as just the version number.
    if (fields[0].slice(0, 4) === 'CEF:') {
      fields[0] = fields[0].slice(4);
    }
    const ext = cefBody.slice(i);
    return { fields, ext };
  };

  // Parse the extension block. CEF extensions are space-separated
  // `key=value` pairs where `value` may contain spaces UP TO the
  // next `key=` token (keys can't contain `=` or whitespace, so
  // we look ahead for the next ` <ident>=` boundary). Backslash
  // escapes (`\=`, `\\`, `\n`, `\r`) are honoured inside values.
  // Returns an object map.
  const _RE_EXT_KEY_BOUNDARY = /\s+([A-Za-z_][A-Za-z0-9_.]*)=/g;
  const parseExt = (s) => {
    const out = Object.create(null);
    if (!s) return out;
    // Trim leading whitespace.
    let str = s.replace(/^\s+/, '');
    if (!str) return out;
    // Scan for `key=` tokens at the start; the value runs until the
    // next ` key=` boundary (or end of string).
    const firstEq = str.indexOf('=');
    if (firstEq < 0) return out;
    // First key is everything up to the first `=`.
    let k = str.slice(0, firstEq);
    let rest = str.slice(firstEq + 1);
    // Find subsequent ` <ident>=` boundaries in `rest`. We walk
    // them in order, slicing values out at each boundary.
    while (true) {
      _RE_EXT_KEY_BOUNDARY.lastIndex = 0;
      const m = _RE_EXT_KEY_BOUNDARY.exec(rest);
      if (!m) {
        // No further boundary — `rest` is the final value.
        out[k] = unescapeExtValue(rest);
        break;
      }
      // Value runs from start of `rest` up to (but not including)
      // the matched whitespace.
      out[k] = unescapeExtValue(rest.slice(0, m.index));
      k = m[1];
      rest = rest.slice(m.index + m[0].length);
    }
    return out;
  };

  const unescapeExtValue = (s) => {
    if (s.indexOf('\\') < 0) return s;
    let out = '';
    let i = 0;
    const n = s.length;
    while (i < n) {
      const ch = s.charCodeAt(i);
      if (ch === 0x5C && i + 1 < n) {
        const nx = s.charAt(i + 1);
        if (nx === 'n') out += '\n';
        else if (nx === 'r') out += '\r';
        else if (nx === 't') out += '\t';
        else out += nx;             // \=, \\, \|, \", etc.
        i += 2;
        continue;
      }
      out += s.charAt(i);
      i++;
    }
    return out;
  };

  const tokenize = (line, _mtime) => {
    if (!line) return null;
    // Tolerate UTF-8 BOM on the first line.
    let s = line;
    if (s.charCodeAt(0) === 0xFEFF) s = s.slice(1);
    const parts = splitHeader(s);
    if (!parts) return null;
    const ext = parseExt(parts.ext);
    if (!extSchema) {
      extSchema = Object.keys(ext).slice(0, _TL_CEF_MAX_EXT_COLUMNS);
      extSchemaIndex = Object.create(null);
      for (let i = 0; i < extSchema.length; i++) extSchemaIndex[extSchema[i]] = i;
    }
    // Build the row: 7 header cells + N ext cells + 1 _extra cell.
    const cells = new Array(_TL_CEF_HEADER_COLS.length + extSchema.length + 1).fill('');
    for (let i = 0; i < _TL_CEF_HEADER_COLS.length; i++) {
      cells[i] = parts.fields[i] || '';
    }
    let extras = null;
    const keys = Object.keys(ext);
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i];
      const idx = extSchemaIndex[k];
      if (idx !== undefined) {
        cells[_TL_CEF_HEADER_COLS.length + idx] = ext[k];
      } else {
        if (!extras) extras = Object.create(null);
        extras[k] = ext[k];
      }
    }
    if (extras) {
      try { cells[cells.length - 1] = JSON.stringify(extras); }
      catch (_) { cells[cells.length - 1] = ''; }
    }
    return cells;
  };

  const getColumns = (_width) => {
    const cols = _TL_CEF_HEADER_COLS.slice();
    if (extSchema) {
      for (let i = 0; i < extSchema.length; i++) cols.push(extSchema[i]);
    }
    cols.push('_extra');
    return cols;
  };

  // Histogram stack — always Severity (column 6 in the canonical
  // header).
  const getDefaultStackColIdx = () => _TL_CEF_HEADER_COLS.indexOf('Severity');

  const getFormatLabel = () => 'CEF';

  return { tokenize, getColumns, getDefaultStackColIdx, getFormatLabel };
}

// ── LEEF (Log Event Extended Format — IBM QRadar) tokeniser ──────
// LEEF is QRadar's analogue to CEF — same idea, slightly different
// shape:
//
//   LEEF:1.0|Vendor|Product|Version|EventID|<TAB>k=v<TAB>k=v\u2026
//   LEEF:2.0|Vendor|Product|Version|EventID|<delim>|k=v<delim>k=v\u2026
//
// LEEF 1.0 always separates extension key=value pairs with literal
// tabs (`\\x09`). LEEF 2.0 adds an optional 6th pipe-delimited
// header field carrying the extension delimiter character (a
// single character or a `\\xXX` hex escape). When that 6th field
// is empty / missing, the default is still tab.
//
// Like CEF, LEEF is overwhelmingly tunnelled inside syslog \u2014 the
// tokeniser locates the literal `LEEF:` marker and discards
// anything before it.
//
// Schema:
//   \u2022 5 fixed header columns: Version, Vendor, Product,
//     ProductVersion, EventID. (LEEF 2.0's 6th delimiter field is
//     CONSUMED, not emitted as a column \u2014 it controls extension
//     parsing only.)
//   \u2022 Dynamic extension columns locked from the first record's
//     key=value block.
//   \u2022 Trailing `_extra` for unknown keys.
//
// LEEF has no severity column in its header; the de-facto stack-by
// candidate is the `sev` extension key (1\u20139 in the LEEF
// dictionary), with `cat` (event category) as a fallback. If
// neither is in the locked schema we defer to the host-side
// cardinality probe by returning null.
const _TL_LEEF_HEADER_COLS = [
  'Version', 'Vendor', 'Product', 'ProductVersion', 'EventID',
];
const _TL_LEEF_MAX_EXT_COLUMNS = 256;
function _tlMakeLEEFTokenizer() {
  let extSchema = null;
  let extSchemaIndex = null;

  const splitHeader = (line) => {
    if (!line) return null;
    const leefIdx = line.indexOf('LEEF:');
    if (leefIdx < 0) return null;
    const body = line.slice(leefIdx);
    // Walk the body splitting on unescaped `|`. LEEF 1.0 has 5
    // pipes; LEEF 2.0 has 6 (the 6th is the ext delimiter spec).
    const fields = [];
    let cur = '';
    let i = 0;
    const n = body.length;
    // We need to know how many pipes to consume. Peek at the
    // version: `LEEF:1.0` vs `LEEF:2.0`. The version field starts
    // after `LEEF:` and runs until the first `|`.
    let firstPipe = -1;
    for (let j = 5; j < n; j++) {
      const c = body.charCodeAt(j);
      if (c === 0x5C && j + 1 < n) { j++; continue; }   // skip escape
      if (c === 0x7C) { firstPipe = j; break; }
    }
    if (firstPipe < 0) return null;
    const version = body.slice(5, firstPipe);
    // LEEF 1.0 has 5 pipes after the LEEF: marker, producing 5
    // header fields (Version · Vendor · Product · ProductVersion ·
    // EventID); the body after the 5th pipe is the ext. LEEF 2.0
    // has 6 pipes (the 6th carries the ext-delimiter spec).
    //
    // The loop walks pipes and pushes the left-hand side as a
    // field at each one. When we've pushed `wantPipes` fields
    // we've crossed `wantPipes` pipes and the cursor sits at the
    // start of the ext block.
    const wantPipes = (version.startsWith('2')) ? 6 : 5;
    while (i < n && fields.length < wantPipes) {
      const ch = body.charCodeAt(i);
      if (ch === 0x5C && i + 1 < n) {
        cur += body.charAt(i + 1);
        i += 2;
        continue;
      }
      if (ch === 0x7C) {
        fields.push(cur);
        cur = '';
        i++;
        continue;
      }
      cur += body.charAt(i);
      i++;
    }
    if (fields.length < wantPipes) return null;     // malformed
    // First field is `LEEF:<ver>` \u2014 strip the prefix.
    if (fields[0].slice(0, 5) === 'LEEF:') {
      fields[0] = fields[0].slice(5);
    }
    // Determine the ext delimiter. LEEF 1.0 \u2192 always tab. LEEF 2.0
    // \u2192 fields[5] is the delimiter spec; empty defaults to tab.
    let delim = '\t';
    if (wantPipes === 6) {
      const spec = fields[5];
      if (spec) {
        // Hex escape: `\xHH` or `0xHH`. The header walker already
        // stripped any literal backslash via its escape branch, so
        // `\xHH` arrives here as `xHH`. Match either form for
        // belt-and-braces compatibility with parsers that don't
        // unescape the spec.
        const m = /^(?:\\?x|0x)([0-9A-Fa-f]{1,2})$/i.exec(spec);
        if (m) {
          delim = String.fromCharCode(parseInt(m[1], 16));
        } else {
          delim = spec.charAt(0);
        }
      }
      // Drop the delimiter spec from the emitted header columns
      // (it's parser-internal).
      fields.length = 5;
    }
    const ext = body.slice(i);
    return { fields, ext, delim };
  };

  // Parse the extension. LEEF ext is `key=value<delim>key=value\u2026`
  // \u2014 unlike CEF, the delimiter is NOT whitespace, so we can split
  // straightforwardly. Backslash escapes (`\\=`, `\\\\`, `\\n`, `\\r`)
  // and the literal delimiter as `\\<delim>` are honoured inside
  // values.
  const unescapeValue = (s) => {
    if (s.indexOf('\\') < 0) return s;
    let out = '';
    let i = 0;
    const n = s.length;
    while (i < n) {
      const ch = s.charCodeAt(i);
      if (ch === 0x5C && i + 1 < n) {
        const nx = s.charAt(i + 1);
        if (nx === 'n') out += '\n';
        else if (nx === 'r') out += '\r';
        else if (nx === 't') out += '\t';
        else out += nx;
        i += 2;
        continue;
      }
      out += s.charAt(i);
      i++;
    }
    return out;
  };

  const parseExt = (s, delim) => {
    const out = Object.create(null);
    if (!s) return out;
    // Split on the delimiter, honouring `\<delim>` as an escaped
    // literal.
    const pairs = [];
    let cur = '';
    let i = 0;
    const n = s.length;
    while (i < n) {
      const ch = s.charAt(i);
      if (ch === '\\' && i + 1 < n) {
        cur += ch + s.charAt(i + 1);
        i += 2;
        continue;
      }
      if (ch === delim) {
        if (cur.length) pairs.push(cur);
        cur = '';
        i++;
        continue;
      }
      cur += ch;
      i++;
    }
    if (cur.length) pairs.push(cur);
    for (let p = 0; p < pairs.length; p++) {
      const pair = pairs[p];
      const eq = pair.indexOf('=');
      if (eq < 0) continue;
      const k = pair.slice(0, eq);
      const v = pair.slice(eq + 1);
      if (k) out[k] = unescapeValue(v);
    }
    return out;
  };

  const tokenize = (line, _mtime) => {
    if (!line) return null;
    let s = line;
    if (s.charCodeAt(0) === 0xFEFF) s = s.slice(1);
    const parts = splitHeader(s);
    if (!parts) return null;
    const ext = parseExt(parts.ext, parts.delim);
    if (!extSchema) {
      extSchema = Object.keys(ext).slice(0, _TL_LEEF_MAX_EXT_COLUMNS);
      extSchemaIndex = Object.create(null);
      for (let i = 0; i < extSchema.length; i++) extSchemaIndex[extSchema[i]] = i;
    }
    const cells = new Array(_TL_LEEF_HEADER_COLS.length + extSchema.length + 1).fill('');
    for (let i = 0; i < _TL_LEEF_HEADER_COLS.length; i++) {
      cells[i] = parts.fields[i] || '';
    }
    let extras = null;
    const keys = Object.keys(ext);
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i];
      const idx = extSchemaIndex[k];
      if (idx !== undefined) {
        cells[_TL_LEEF_HEADER_COLS.length + idx] = ext[k];
      } else {
        if (!extras) extras = Object.create(null);
        extras[k] = ext[k];
      }
    }
    if (extras) {
      try { cells[cells.length - 1] = JSON.stringify(extras); }
      catch (_) { cells[cells.length - 1] = ''; }
    }
    return cells;
  };

  const getColumns = (_width) => {
    const cols = _TL_LEEF_HEADER_COLS.slice();
    if (extSchema) {
      for (let i = 0; i < extSchema.length; i++) cols.push(extSchema[i]);
    }
    cols.push('_extra');
    return cols;
  };

  // Default stack column: prefer `sev` (LEEF's severity ext key),
  // then `cat` (event category). Both live in the ext schema, not
  // the fixed header.
  const _STACK_CANDIDATES = ['sev', 'severity', 'cat', 'category'];
  const getDefaultStackColIdx = () => {
    if (!extSchema) return null;
    for (let i = 0; i < _STACK_CANDIDATES.length; i++) {
      const idx = extSchemaIndex[_STACK_CANDIDATES[i]];
      if (idx !== undefined) {
        return _TL_LEEF_HEADER_COLS.length + idx;
      }
    }
    return null;
  };

  const getFormatLabel = () => 'LEEF';

  return { tokenize, getColumns, getDefaultStackColIdx, getFormatLabel };
}

// ── logfmt tokeniser (Heroku / Logrus / Go services) ──────────────
// Logfmt is a flat `key=value key="quoted value" key=` line format
// without any header — it's the de-facto structured-log shape used
// by Heroku's router logs, Logrus, Go services, Hashicorp tools
// (Consul, Vault, Nomad), and many cloud-native pipelines. Spec:
// https://brandur.org/logfmt.
//
// Grammar (per line):
//   pair    := key '=' value | key
//   key     := [A-Za-z_][\w.\-/]*
//   value   := '"' (escaped-char | non-quote)* '"'   ; quoted form
//            | non-whitespace*                         ; bare form
//   line    := pair (whitespace+ pair)*
//
// Quoted-value escapes: `\"` `\\` `\n` `\r` `\t`. Bare values run
// until the next ASCII whitespace. Pairs without `=` (bare keys)
// are recorded with the empty string.
//
// Schema is locked from the first valid line's key set (cap 256);
// later lines spill unknown keys into a trailing `_extra` JSON
// sub-object. Default stack column probes the locked schema for
// `[level, severity, lvl, msg, status, method]` (returns null if
// none).
const _TL_LOGFMT_MAX_COLUMNS = 256;
function _tlMakeLogfmtTokenizer() {
  let schema = null;          // string[] | null — locked on first record
  let schemaIndex = null;     // Object<string,number>

  // Walk a logfmt line, returning a flat key -> value map. Returns
  // null when the line carries no `key=value` pair (bare-key-only
  // lines without any `=` are not logfmt — they're free text).
  const parseLine = (line) => {
    let s = line;
    if (s.charCodeAt(0) === 0xFEFF) s = s.slice(1);
    const out = Object.create(null);
    let i = 0;
    const n = s.length;
    let sawPair = false;
    while (i < n) {
      // Skip whitespace.
      while (i < n) {
        const c = s.charCodeAt(i);
        if (c === 0x20 || c === 0x09) i++;
        else break;
      }
      if (i >= n) break;
      // Read key: alnum / underscore / dot / dash / slash.
      const keyStart = i;
      while (i < n) {
        const c = s.charCodeAt(i);
        // Allow letters, digits, _ . - /
        if ((c >= 0x30 && c <= 0x39) ||           // 0-9
            (c >= 0x41 && c <= 0x5A) ||           // A-Z
            (c >= 0x61 && c <= 0x7A) ||           // a-z
            c === 0x5F || c === 0x2E ||           // _ .
            c === 0x2D || c === 0x2F) {           // - /
          i++;
        } else {
          break;
        }
      }
      if (i === keyStart) {
        // Non-key char where a key was expected — skip and continue.
        // This makes the parser tolerant of free-text prefixes.
        i++;
        continue;
      }
      const key = s.slice(keyStart, i);
      // Optional `=value`.
      if (i < n && s.charCodeAt(i) === 0x3D) {
        i++;
        // Quoted or bare value.
        if (i < n && s.charCodeAt(i) === 0x22 /* " */) {
          i++;
          let val = '';
          while (i < n) {
            const c = s.charCodeAt(i);
            if (c === 0x5C && i + 1 < n) {
              const nx = s.charAt(i + 1);
              if (nx === 'n') val += '\n';
              else if (nx === 'r') val += '\r';
              else if (nx === 't') val += '\t';
              else val += nx;                       // \" \\ literal
              i += 2;
              continue;
            }
            if (c === 0x22) { i++; break; }
            val += s.charAt(i);
            i++;
          }
          out[key] = val;
          sawPair = true;
        } else {
          // Bare value: run to next whitespace.
          const valStart = i;
          while (i < n) {
            const c = s.charCodeAt(i);
            if (c === 0x20 || c === 0x09) break;
            i++;
          }
          out[key] = s.slice(valStart, i);
          sawPair = true;
        }
      } else {
        // Bare key (no `=`).
        out[key] = '';
      }
    }
    return sawPair ? out : null;
  };

  const tokenize = (line, _mtime) => {
    if (!line) return null;
    const flat = parseLine(line);
    if (!flat) return null;
    if (!schema) {
      schema = Object.keys(flat).slice(0, _TL_LOGFMT_MAX_COLUMNS);
      schemaIndex = Object.create(null);
      for (let i = 0; i < schema.length; i++) schemaIndex[schema[i]] = i;
    }
    const cells = new Array(schema.length + 1).fill('');
    let extras = null;
    const keys = Object.keys(flat);
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i];
      const idx = schemaIndex[k];
      if (idx !== undefined) {
        cells[idx] = flat[k];
      } else {
        if (!extras) extras = Object.create(null);
        extras[k] = flat[k];
      }
    }
    if (extras) {
      try { cells[schema.length] = JSON.stringify(extras); }
      catch (_) { cells[schema.length] = ''; }
    }
    return cells;
  };

  const getColumns = (_width) => {
    const cols = schema ? schema.slice() : [];
    cols.push('_extra');
    return cols;
  };

  const _STACK_CANDIDATES = [
    'level', 'severity', 'lvl', 'msg', 'status', 'method',
  ];
  const getDefaultStackColIdx = () => {
    if (!schema) return null;
    for (let i = 0; i < _STACK_CANDIDATES.length; i++) {
      const idx = schemaIndex[_STACK_CANDIDATES[i]];
      if (idx !== undefined) return idx;
    }
    return null;
  };

  const getFormatLabel = () => 'logfmt';

  return { tokenize, getColumns, getDefaultStackColIdx, getFormatLabel };
}

// ── W3C Extended Log Format tokeniser (IIS / AWS ELB / ALB /
//    CloudFront / generic W3C) ────────────────────────────────────
// W3C Extended Log File Format (https://www.w3.org/TR/WD-logfile)
// is the schema-on-disk format used by Microsoft IIS, AWS ELB
// (classic), AWS ALB (Application Load Balancer), AWS CloudFront,
// AWS NLB (TCP variant), and a long tail of HTTP-adjacent
// services. Files start with `#`-prefixed directives that
// describe the per-file column layout; data rows are delimited
// by either single ASCII space (IIS) or tab (ALB / CloudFront).
//
// Directive set:
//   #Software, #Version, #Date, #Start-Date, #End-Date, #Remark
//   are metadata and produce no row data.
//   #Fields:  defines (or resets) the schema. Cap 256 cols.
//
// Schema-driven projection:
//   - Column names may include parentheses (`cs(User-Agent)`,
//     `cs(Referer)`, `cs(Cookie)`); these are passed through
//     verbatim. Aside from `(`/`)`/`-` the W3C identifier set
//     is conservative.
//   - Empty values are encoded as `-` (literal hyphen) per spec
//     — substituted for the empty string.
//   - IIS encodes spaces inside field values as `+` (URL-encode-
//     style); decoded back to space at parse time. ALB and
//     CloudFront use `%20` instead, which we leave untouched
//     (the tokeniser does NOT do general URL decoding — only
//     the `+`→space substitution that IIS conventions require).
//
// Synthesised Timestamp column:
//   IIS, CloudFront: `date` + `time` are joined into ISO 8601
//     (`YYYY-MM-DDTHH:MM:SSZ`) at synthetic column index 0.
//   ALB: `time` field is already ISO 8601 — pass through.
//   ELB: `timestamp` field is already ISO 8601 — pass through.
//   Generic: if both `date` and `time` columns exist, synthesise.
//   The synthesised column is always named `Timestamp` and sits
//   at index 0 ahead of the parsed schema, matching what the
//   Timeline grid auto-detects on first paint.
//
// Format-label discrimination — the tokeniser inspects the
// `#Software` directive (if any) and the first observed
// `#Fields:` schema to pick a label:
//   IIS:        `#Software` contains "Microsoft Internet
//               Information Services".
//   AWS ALB:    schema contains `target_status_code` or
//               `request_processing_time`.
//   AWS ELB:    schema contains `backend_status_code` (without
//               `target_*` keys).
//   CloudFront: schema contains `x-edge-location`.
//   Generic:    `#Fields:` present but no source match → the
//               label is `W3C Extended`.
//
// Delimiter detection:
//   On the first data row after a `#Fields:` directive, count
//   tabs vs spaces. Whichever delimiter has at least
//   `fields - 1` occurrences becomes the row delimiter for this
//   schema. This handles IIS (space) and ALB / CloudFront (tab)
//   from the same parser without requiring a static table.
const _TL_W3C_MAX_COLUMNS = 256;
function _tlMakeW3CTokenizer() {
  let schema = null;          // string[] — set by `#Fields:` directive
  let schemaIndex = null;     // Object<string, number>
  let delim = null;           // ' ' | '\t' — locked on first data row
  let label = 'W3C Extended'; // refined by #Software / schema content
  let dateIdx = -1;           // index of `date` in schema, -1 if absent
  let timeIdx = -1;           // index of `time` in schema
  let synthesisedTimestamp = false; // true when col 0 = synthesised
  let softwareLineSeen = false;     // tracks #Software for IIS detect

  const refineLabel = () => {
    // Order: most specific first.
    if (softwareLineSeen) return;          // IIS already locked
    if (!schema) return;
    const has = (k) => schemaIndex && schemaIndex[k] !== undefined;
    if (has('x-edge-location')) { label = 'AWS CloudFront'; return; }
    if (has('target_status_code') || has('request_processing_time')) {
      label = 'AWS ALB'; return;
    }
    if (has('backend_status_code')) { label = 'AWS ELB'; return; }
    label = 'W3C Extended';
  };

  // Decode IIS-style `+` → space inside a field value. ALB /
  // CloudFront use `%20` for spaces; we leave those untouched
  // (general URL decoding is out of scope and would corrupt
  // legitimate `%` chars in cookies / referers).
  const decodeIIS = (s) => {
    if (!s || s.indexOf('+') < 0) return s;
    let out = '';
    for (let i = 0; i < s.length; i++) {
      out += s.charAt(i) === '+' ? ' ' : s.charAt(i);
    }
    return out;
  };

  const tokenize = (line, _mtime) => {
    if (!line) return null;
    let s = line;
    if (s.charCodeAt(0) === 0xFEFF) s = s.slice(1);
    if (!s.length) return null;

    // Directive lines start with `#`. Handle the spec set; ignore
    // unknown directives so future W3C extensions don't break the
    // parse.
    if (s.charCodeAt(0) === 0x23 /* '#' */) {
      // `#Fields:` — schema definition / reset.
      const fm = /^#Fields:\s*(.+)$/i.exec(s);
      if (fm) {
        const raw = fm[1].trim();
        // Fields are whitespace-separated in the directive.
        const fields = raw.split(/\s+/).slice(0, _TL_W3C_MAX_COLUMNS);
        schema = fields;
        schemaIndex = Object.create(null);
        for (let i = 0; i < fields.length; i++) schemaIndex[fields[i]] = i;
        dateIdx = schemaIndex['date'] !== undefined
          ? schemaIndex['date'] : -1;
        timeIdx = schemaIndex['time'] !== undefined
          ? schemaIndex['time'] : -1;
        synthesisedTimestamp = (dateIdx >= 0 && timeIdx >= 0);
        delim = null;             // re-detect on next data row
        refineLabel();
        return null;
      }
      // `#Software:` — used for IIS label detection.
      const sm = /^#Software:\s*(.+)$/i.exec(s);
      if (sm) {
        if (/Microsoft\s+Internet\s+Information\s+Services/i.test(sm[1])) {
          label = 'IIS W3C';
          softwareLineSeen = true;
        }
        return null;
      }
      // Other comment / metadata directives — silently ignore.
      return null;
    }

    // Data row. Need a schema; without one we can't project.
    if (!schema || !schema.length) return null;

    // Lock delimiter on the first data row.
    if (delim === null) {
      const tabs = (s.match(/\t/g) || []).length;
      const spaces = (s.match(/ /g) || []).length;
      if (tabs >= schema.length - 1) delim = '\t';
      else if (spaces >= schema.length - 1) delim = ' ';
      else delim = (tabs > spaces) ? '\t' : ' ';
    }

    // Split. W3C does not define quoting; values can't contain
    // the delimiter (consumers must encode them — IIS uses `+` for
    // space, AWS uses `%20`).
    const parts = s.split(delim);
    // Width-mismatched rows: pad short / truncate long. Don't
    // emit `_extra` — W3C is fixed-width per `#Fields:` directive.
    const cells = new Array(schema.length).fill('');
    const upTo = Math.min(parts.length, schema.length);
    for (let i = 0; i < upTo; i++) {
      let v = parts[i];
      if (v === '-') v = '';
      else if (v && v.indexOf('+') >= 0) v = decodeIIS(v);
      cells[i] = v;
    }

    // Synthesise leading Timestamp column when both `date` and
    // `time` were declared. ISO 8601, UTC convention (matches
    // IIS `u_ex*.log` and CloudFront documented behaviour).
    if (synthesisedTimestamp) {
      const d = cells[dateIdx];
      const t = cells[timeIdx];
      const ts = (d && t) ? (d + 'T' + t + 'Z') : '';
      return [ts].concat(cells);
    }
    return cells;
  };

  // Columns: prepend `Timestamp` when synthesised. No `_extra`.
  const getColumns = (_width) => {
    if (!schema) return [];
    const cols = schema.slice();
    if (synthesisedTimestamp) cols.unshift('Timestamp');
    return cols;
  };

  // Histogram stack candidates spanning IIS + AWS variants.
  const _STACK_CANDIDATES = [
    'sc-status', 'elb_status_code', 'target_status_code',
    'sc-status-code', 'status', 'cs-method', 'method',
    'cs-uri-stem', 's-sitename',
  ];
  const getDefaultStackColIdx = () => {
    if (!schema) return null;
    const offset = synthesisedTimestamp ? 1 : 0;
    for (let i = 0; i < _STACK_CANDIDATES.length; i++) {
      const idx = schemaIndex[_STACK_CANDIDATES[i]];
      if (idx !== undefined) return idx + offset;
    }
    return null;
  };

  const getFormatLabel = () => label;

  return { tokenize, getColumns, getDefaultStackColIdx, getFormatLabel };
}

// ── Apache error_log tokeniser ────────────────────────────────────
// Apache HTTP Server's error log (the `ErrorLog` directive output,
// distinct from access logs which we already cover via CLF) has
// a structured-but-not-quite-tabular shape:
//
//   [Tue Apr 30 14:23:11.123456 2024] [core:error] [pid 12345] [client 10.0.0.5:51234] AH00037: Symbolic link not allowed
//   [Tue Apr 30 14:23:12 2024] [mpm_event:notice] [pid 12345:tid 140] AH00489: Apache/2.4.58 (Unix) configured -- resuming normal operations
//   [Tue Apr 30 14:23:13 2024] [proxy_fcgi:error] [pid 12346] (70007)The timeout specified has expired: AH01075: Error dispatching request to :
//
// The format is bracketed metadata followed by a free-text
// message. The first bracket is always the timestamp; subsequent
// brackets are key=value-ish (`module:level`, `pid X[:tid Y]`,
// `client IP[:PORT]`). After the brackets, an optional
// `AH<5digits>:` token tags the canonical Apache error code,
// then the human-readable message.
//
// Schema (fixed 8 columns):
//   1 Timestamp  — parsed from the leading [...] block
//   2 Module     — left half of `[module:level]`
//   3 Severity   — right half (emerg/alert/crit/error/warn/
//                  notice/info/debug/trace1..trace8)
//   4 PID        — `[pid 12345]` or `[pid X:tid Y]`
//   5 TID        — optional `[pid X:tid Y]`, blank otherwise
//   6 Client     — optional `[client IP[:PORT]]`, blank otherwise
//   7 ErrorCode  — optional `AH\\d{5}` token at message start
//   8 Message    — everything else (preserves embedded brackets,
//                  parens, status text)
//
// Default histogram stack is `Severity`. Stateless — schema is
// fixed; no `_extra` column.
const _TL_APACHE_ERROR_COLS = [
  'Timestamp', 'Module', 'Severity', 'PID', 'TID', 'Client',
  'ErrorCode', 'Message',
];

// Apache day / month abbreviations. The day-of-week is purely
// informational (it's redundant with the date) and we ignore it.
const _TL_APACHE_ERR_MON = {
  jan:0, feb:1, mar:2, apr:3, may:4, jun:5,
  jul:6, aug:7, sep:8, oct:9, nov:10, dec:11,
};

// `[Tue Apr 30 14:23:11.123456 2024]` — day name, month name,
// day-of-month (1 or 2 digits), HH:MM:SS, optional `.usec`,
// 4-digit year. Apache always emits the year so we don't need
// the syslog-3164 mtime-roll trick.
const _TL_APACHE_ERR_TS_RE =
  /^\[(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {1,2}(\d{1,2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d+))? (\d{4})\]/;

/* safeRegex: builtin */
const _TL_APACHE_ERR_LINE_RE = new RegExp(
  '^' +
  // Timestamp bracket.
  '\\[(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {1,2}\\d{1,2} \\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)? \\d{4}\\] ' +
  // Module:level bracket.
  '\\[(\\w+):(\\w+)\\]' +
  // Optional pid bracket — `[pid N]` or `[pid N:tid M]`.
  '(?: \\[pid (\\d+)(?::tid (\\d+))?\\])?' +
  // Optional client bracket — `[client IP]` or `[client IP:PORT]`.
  '(?: \\[client ([^\\]]+)\\])?' +
  // The rest of the line is the message. We keep the leading
  // space (if any) trimmed off in the parser.
  '(.*)$'
);

function _tlMakeApacheErrorTokenizer() {
  const tokenize = (line, _mtime) => {
    if (!line) return null;
    let s = line;
    if (s.charCodeAt(0) === 0xFEFF) s = s.slice(1);
    if (!s.length || s.charAt(0) !== '[') return null;
    const tsMatch = _TL_APACHE_ERR_TS_RE.exec(s);
    if (!tsMatch) return null;
    const m = _TL_APACHE_ERR_LINE_RE.exec(s);
    if (!m) return null;
    // Build ISO 8601 timestamp from the named groups in tsMatch.
    const monIdx = _TL_APACHE_ERR_MON[tsMatch[1].toLowerCase()];
    const day = String(+tsMatch[2]).padStart(2, '0');
    const mon = String(monIdx + 1).padStart(2, '0');
    const usec = tsMatch[6] ? '.' + tsMatch[6].padEnd(6, '0').slice(0, 6) : '';
    const ts = tsMatch[7] + '-' + mon + '-' + day +
               'T' + tsMatch[3] + ':' + tsMatch[4] + ':' + tsMatch[5] + usec;
    const module_ = m[1] || '';
    const severity = m[2] || '';
    const pid = m[3] || '';
    const tid = m[4] || '';
    const client = m[5] || '';
    let rest = (m[6] || '').replace(/^\s+/, '');
    // Optional `AH\d{5}:` error-code token at message start.
    let errCode = '';
    const ah = /^AH(\d{5}):\s*/.exec(rest);
    if (ah) {
      errCode = 'AH' + ah[1];
      rest = rest.slice(ah[0].length);
    }
    return [ts, module_, severity, pid, tid, client, errCode, rest];
  };

  const getColumns = (_width) => _TL_APACHE_ERROR_COLS.slice();

  // Histogram stack column = Severity (column index 2).
  const getDefaultStackColIdx = () => 2;

  const getFormatLabel = () => 'Apache error_log';

  return { tokenize, getColumns, getDefaultStackColIdx, getFormatLabel };
}

// ── Generic space-delimited access log tokeniser ───────────────────
// Covers space-delimited access / audit logs that do NOT match the
// Apache / Nginx CLF shape — notably Pulse Secure / Ivanti Connect
// Secure exports, custom proxy logs, and any hand-rolled access log
// where:
//
//   - Column 1 is a recognisable timestamp (ISO 8601 with space or
//     `T` separator, the Ivanti `YYYY-MM-DD--HH-MM-SS` double-dash
//     form, or epoch-seconds / epoch-ms digits).
//   - Subsequent columns are either bare (no whitespace inside) or
//     wrapped in `"…"` (backslash-escaped quotes honoured the same
//     way CLF does it — `\"` and `\\` are decoded, other `\X`
//     passes through).
//
// Shape, using the user's Pulse Secure example:
//
//   2025-05-15--17-43-27 64.62.197.102 TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256 \
//     "GET /mifs/…" 277 "-" "Mozilla/5.0 (…)"
//
// There is no fixed column count — different emitters ship different
// schemas. We tokenise into a dense row and emit synthetic
// `time`, `field_2`, …, `field_N` column names. The first valid row
// locks the column count; later rows pad / trim to that width so the
// RowStore stays dense.
//
// Canonical fingerprint: the "TLS access log" shape (8 fields —
// timestamp, client IP, TLS proto, cipher, quoted request, bytes,
// quoted referer, quoted UA) gets CLF-style friendly names
// (`time`, `ip`, `tls_version`, `tls_cipher`, `request`, `bytes`,
// `referer`, `user_agent`) so the Timeline auto-axis and the IP /
// request columns line up without manual column renaming.
//
// Stateless per-line tokeniser; histogram stack defaults to the
// last-but-one column (Referer / last quoted metadata) — the router
// will overlay a cardinality probe if that column's distinct count
// exceeds the stack-column gate.
//
// Why this isn't the CLF tokeniser with a looser timestamp check:
// the CLF tokeniser is a fixed-shape lexer pinned to a `[date]`
// bracketed timestamp at field 4 and a quoted request at field 5.
// Changing its shape to admit bare timestamps in col 1 would collapse
// every non-CLF space-delimited line onto a wider CLF row and
// confuse the CLF-specific column naming. Keep them separate so
// either format can evolve without regressing the other.

// Accepts any of the timestamp shapes `_tlParseTimestamp` recognises
// with a time component (Epoch s/ms, ISO, Ivanti double-dash, a few
// syslog-style compacts). The probe is lexical only — we don't need
// Date.parse agreement to decide "this line starts with a timestamp",
// only that the token shape is unambiguously temporal. The
// `_tlParseTimestamp` call happens later per-row on the resolved
// cell — that's the authoritative parse.
const _TL_ACCESS_LOG_TS_RE =
  /^(?:-?\d{10}|-?\d{13}|\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\d{4}-\d{2}-\d{2}--\d{2}-\d{2}-\d{2}|\d{4}\/\d{2}\/\d{2}[ T]\d{2}:\d{2}:\d{2})(?=\s)/;

// Lightweight validator for the access-log timestamp column —
// keeps the tokeniser self-contained (no dependency on the full
// `_tlParseTimestamp` regex waterfall) and, crucially, usable from
// the worker shim where `_tlParseTimestamp` isn't mirrored. Rejects
// shapes that look temporal but encode an impossible calendar date
// (e.g. `2025-02-31--00-00-00`) — a loose accept here would admit
// any space-delimited file with a leading digit run.
function _tlAccessLogTimestampOk(s) {
  if (typeof s !== 'string' || !s) return false;
  // Epoch — any 10 or 13 digit integer is accepted.
  if (/^-?\d{10}$/.test(s) || /^-?\d{13}$/.test(s)) return true;
  // ISO 8601 with time — delegate to Date.parse after normalisation.
  if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/.test(s)
      || /^\d{4}\/\d{2}\/\d{2}[ T]\d{2}:\d{2}:\d{2}/.test(s)) {
    const norm = s.replace(' ', 'T').replace(/\//g, '-');
    return Number.isFinite(Date.parse(norm));
  }
  // Ivanti double-dash form `YYYY-MM-DD--HH-MM-SS`.
  const m = /^(\d{4})-(\d{2})-(\d{2})--(\d{2})-(\d{2})-(\d{2})$/.exec(s);
  if (m) {
    const mo = +m[2], d = +m[3], hh = +m[4], mm = +m[5], ss = +m[6];
    return (mo >= 1 && mo <= 12 && d >= 1 && d <= 31
            && hh < 24 && mm < 60 && ss < 60);
  }
  return false;
}

// CLF-style read: unquoted run up to the next space, or `"..."`
// quoted run with `\\` / `\"` decoded. Returns `{ token, next }`
// where `next` is the index past the trailing whitespace.
function _tlReadAccessLogField(line, i) {
  const len = line.length;
  if (i >= len) return null;
  if (line.charCodeAt(i) === 0x22 /* " */) {
    // Quoted field — CLF-style backslash escapes.
    i++;
    let result = '';
    let runStart = i;
    while (i < len) {
      const c = line.charCodeAt(i);
      if (c === 0x5C /* \ */ && i + 1 < len) {
        const next = line.charCodeAt(i + 1);
        if (next === 0x22 /* " */ || next === 0x5C) {
          if (i > runStart) result += line.slice(runStart, i);
          result += String.fromCharCode(next);
          i += 2;
          runStart = i;
          continue;
        }
        i += 2;
        continue;
      }
      if (c === 0x22) {
        if (i > runStart) result += line.slice(runStart, i);
        i++;                              // step past closing `"`
        while (i < len && line.charCodeAt(i) === 0x20) i++;
        return { token: result, next: i };
      }
      i++;
    }
    return null;                          // unterminated
  }
  // Unquoted — read to next space.
  const start = i;
  while (i < len && line.charCodeAt(i) !== 0x20) i++;
  const token = line.slice(start, i);
  while (i < len && line.charCodeAt(i) === 0x20) i++;
  return { token, next: i };
}

// "TLS access log" fingerprint — 8 columns:
//   1 timestamp
//   2 client IP     (dotted-quad v4 or `:`-containing v6)
//   3 TLS version   (`TLSv1.0` .. `TLSv1.3` / `SSLv3`)
//   4 cipher        (uppercase letters + digits + `-`)
//   5 request       (quoted)
//   6 bytes         (digits)
//   7 referer       (quoted)
//   8 user agent    (quoted)
const _TL_ACCESS_LOG_TLS_COLS = [
  'time', 'ip', 'tls_version', 'tls_cipher', 'request',
  'bytes', 'referer', 'user_agent',
];

const _TL_ACCESS_LOG_TLS_PROTO_RE = /^(?:TLSv1(?:\.[0-3])?|SSLv[23])$/;

function _tlMakeAccessLogTokenizer() {
  let columns = null;
  let fingerprint = '';                   // 'tls' | 'generic' | ''

  const buildColumns = (cells) => {
    // TLS-access-log fingerprint: exactly 8 cells, col 3 looks
    // like a TLS version, col 6 is all digits (bytes). Bail to
    // the generic naming if any of these fail.
    if (cells.length === 8
        && typeof cells[2] === 'string' && _TL_ACCESS_LOG_TLS_PROTO_RE.test(cells[2])
        && typeof cells[5] === 'string' && /^\d+$/.test(cells[5])) {
      fingerprint = 'tls';
      return _TL_ACCESS_LOG_TLS_COLS.slice();
    }
    fingerprint = 'generic';
    const out = ['time'];
    for (let i = 1; i < cells.length; i++) out.push('field_' + (i + 1));
    return out;
  };

  const tokenize = (line, _mtime) => {
    if (!line) return null;
    let s = line;
    if (s.charCodeAt(0) === 0xFEFF) s = s.slice(1);
    if (!s.length) return null;
    // Quick reject: must open with a recognised timestamp shape.
    if (!_TL_ACCESS_LOG_TS_RE.test(s)) return null;

    const cells = [];
    let i = 0;
    const len = s.length;
    while (i < len) {
      const f = _tlReadAccessLogField(s, i);
      if (!f) break;                      // unterminated quoted field
      cells.push(f.token);
      if (f.next === i) break;            // guard against zero-width reads
      i = f.next;
    }
    if (cells.length < 2) return null;    // must have at least ts + one
    // Verify column 1 actually parses as a timestamp. Cheap insurance
    // — the lexical regex above is permissive by design.
    if (!_tlAccessLogTimestampOk(cells[0])) return null;
    if (!columns) columns = buildColumns(cells);
    return cells;
  };

  const getColumns = (_width) => columns ? columns.slice() : [];
  // For the TLS fingerprint, stack on TLS version (col 2) — low
  // cardinality, useful. For the generic case, leave it to the
  // host-side cardinality probe.
  const getDefaultStackColIdx = () => (fingerprint === 'tls' ? 2 : null);
  const getFormatLabel = () =>
    fingerprint === 'tls' ? 'TLS Access Log' : 'Access Log';
  return { tokenize, getColumns, getDefaultStackColIdx, getFormatLabel };
}

function _tlMakeZeekTokenizer() {
  // Defaults match the Zeek convention; overridden on the fly if the
  // file's preamble carries a `#set_separator` / `#unset_field` /
  // `#empty_field` directive with non-default values.
  let unsetField = '-';
  let emptyField = '(empty)';
  let fieldsCols = null;     // resolved from `#fields`
  let zeekPath = '';         // resolved from `#path`
  let stackColIdx = null;    // resolved from `_TL_ZEEK_STACK_BY_PATH`

  const tokenize = (line, _mtime) => {
    if (!line) return null;
    if (line.charCodeAt(0) === 0x23 /* '#' */) {
      // Directive line. Tab-separated: `#name\tvalue\tvalue\t…`.
      const parts = line.split('\t');
      const name = parts[0];
      switch (name) {
        case '#fields':
          // Slice off the leading `#fields` and keep the rest.
          fieldsCols = parts.slice(1);
          break;
        case '#path':
          zeekPath = parts[1] || '';
          break;
        case '#unset_field':
          if (parts[1] !== undefined) unsetField = parts[1];
          break;
        case '#empty_field':
          if (parts[1] !== undefined) emptyField = parts[1];
          break;
        // `#separator`, `#set_separator`, `#types`, `#open`, `#close`
        // are recognised but ignored — we always tab-split (the sniff
        // already verified `#separator \x09` at line 0) and we don't
        // type-coerce cells (the grid renders strings).
        default:
          break;
      }
      return null;
    }
    // Data row. Split on tab and replace NILVALUEs with empty cells.
    const cells = line.split('\t');
    for (let i = 0; i < cells.length; i++) {
      if (cells[i] === unsetField || cells[i] === emptyField) cells[i] = '';
    }
    return cells;
  };

  const getColumns = (width) => {
    if (Array.isArray(fieldsCols) && fieldsCols.length > 0) {
      // Resolve the default stack column NOW (after the schema is
      // known, before the host-side cardinality probe runs).
      const stackName = _TL_ZEEK_STACK_BY_PATH[zeekPath] || null;
      if (stackName) {
        const idx = fieldsCols.indexOf(stackName);
        if (idx >= 0) stackColIdx = idx;
      }
      return fieldsCols.slice();
    }
    // No `#fields` header — fall back to synthetic names. Shouldn't
    // happen in practice (the sniff requires `#separator`, which is
    // always paired with `#fields`), but stay defensive.
    const cols = [];
    for (let i = 0; i < width; i++) cols.push('col ' + (i + 1));
    return cols;
  };

  const getDefaultStackColIdx = () => stackColIdx;
  const getFormatLabel = () =>
    zeekPath ? ('Zeek (' + zeekPath + ')') : 'Zeek';

  return { tokenize, getColumns, getDefaultStackColIdx, getFormatLabel };
}

// Canonical Apache CLF column names. The Combined Log Format (Apache
// `LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\""`)
// emits 9 fields; the older Common Log Format (no referer / UA) emits 7.
// Anything else falls back to synthetic `col N` names. The `time`
// column lands at index 3 — `_tlAutoDetectTimestampCol` will pick it
// up automatically thanks to the header hint regex (`time|timestamp|...`).
const _TL_CLF_COMBINED_COLS = ['ip', 'ident', 'auth', 'time', 'request',
                               'status', 'bytes', 'referer', 'user_agent'];
const _TL_CLF_COMMON_COLS   = ['ip', 'ident', 'auth', 'time', 'request',
                               'status', 'bytes'];
function _tlCanonicalLogColumns(width) {
  if (width === 9) return _TL_CLF_COMBINED_COLS.slice();
  if (width === 7) return _TL_CLF_COMMON_COLS.slice();
  const cols = [];
  for (let i = 0; i < width; i++) cols.push(`col ${i + 1}`);
  return cols;
}


// Bucket presets.
const TIMELINE_BUCKETS_TARGET = 80;
const TIMELINE_BUCKET_OPTIONS = [
  { id: 'auto', label: 'Auto', ms: null },
  { id: '1s', label: '1 sec', ms: 1_000 },
  { id: '10s', label: '10 sec', ms: 10_000 },
  { id: '1m', label: '1 min', ms: 60_000 },
  { id: '5m', label: '5 min', ms: 300_000 },
  { id: '15m', label: '15 min', ms: 900_000 },
  { id: '1h', label: '1 hour', ms: 3_600_000 },
  { id: '6h', label: '6 hour', ms: 21_600_000 },
  { id: '1d', label: '1 day', ms: 86_400_000 },
  { id: '1w', label: '1 week', ms: 604_800_000 },
];

// Stack palette — 36 perceptually distinct colours that stay legible on both
// light and dark backgrounds.  Every unique stack value gets its own colour;
// when more values exist than palette entries the index wraps via modulo.
const TIMELINE_STACK_PALETTE = [
  '#4f8cff', '#f59e0b', '#22c55e', '#ef4444', '#a855f7',
  '#06b6d4', '#ec4899', '#84cc16', '#64748b', '#f97316',
  '#14b8a6', '#e11d48', '#8b5cf6', '#0ea5e9', '#d946ef',
  '#65a30d', '#0891b2', '#db2777', '#7c3aed', '#059669',
  '#ca8a04', '#dc2626', '#2563eb', '#c026d3', '#16a34a',
  '#ea580c', '#0d9488', '#9333ea', '#0284c7', '#be185d',
  '#4d7c0f', '#b45309', '#6d28d9', '#047857', '#a21caf',
  '#9f1239',
];
const TIMELINE_GRID_DEFAULT_H = 320;
const TIMELINE_GRID_MIN_H = 160;
const TIMELINE_CHART_DEFAULT_H = 220;
const TIMELINE_CHART_MIN_H = 120;
const TIMELINE_CHART_MAX_H = 600;

// Top-values card width presets (S / M / L)
const TIMELINE_CARD_SIZES = { S: 220, M: 300, L: 420 };
const TIMELINE_CARD_SIZE_DEFAULT = 'M';

// Extraction patterns. URL = http(s) prefix; Hostname = contains a dot, no whitespace.
const TL_URL_RE = /\bhttps?:\/\/[^\s"'<>`()\[\]{}]+/i;
const TL_HOSTNAME_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;
const TL_HOSTNAME_INLINE_RE = /\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){1,})\b/i;

// EVTX forensic-grade KV fields. The Extract dialog pre-checks these in its
// Auto tab when the file is EVTX, and the best-effort auto-extract pass
// (`_autoExtractBestEffort`) treats them as always-eligible regardless of
// per-field match coverage so sparse-but-investigatable fields (LogonType,
// IpAddress…) still surface on first open.
const TIMELINE_FORENSIC_EVTX_FIELDS_SET = new Set([
  'CommandLine', 'ParentCommandLine', 'TargetUserName', 'SubjectUserName',
  'ProcessName', 'NewProcessName', 'IpAddress', 'LogonType',
]);

// Regex presets offered on the Extract popup.
const TL_REGEX_PRESETS = [
  { label: 'IPv4 address', pattern: '\\b(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}\\b', group: 0 },
  { label: 'UUID v4', pattern: '\\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b', group: 0, flags: 'i' },
  { label: 'Hex hash (MD5 / SHA1 / SHA256)', pattern: '\\b(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})\\b', group: 0, flags: 'i' },
  { label: 'Email address', pattern: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b', group: 0 },
  { label: 'Windows path', pattern: '[A-Za-z]:\\\\(?:[^\\\\\\s\\"\\<>|?*]+\\\\)*[^\\\\\\s\\"\\<>|?*]+', group: 0 },
  { label: 'PID / integer', pattern: '\\b\\d{1,7}\\b', group: 0 },
];

// ════════════════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════════════════
function _tlParseTimestamp(s) {
  if (s == null) return NaN;
  if (typeof s === 'number') return s;
  const str = String(s).trim();
  if (!str) return NaN;
  // Epoch seconds / milliseconds.
  if (/^-?\d{10}$/.test(str)) return Number(str) * 1000;
  if (/^-?\d{13}$/.test(str)) return Number(str);
  // ISO datetime (with time component).
  if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/.test(str)) {
    // Normalise the separator to 'T' and common tz suffixes (" UTC",
    // " GMT") to 'Z' so Date.parse sees a valid ISO 8601 string.
    // Without this, inputs like "2022-11-20 22:42:44 UTC" (produced by
    // the SQLite browser-history renderer) become "2022-11-20T22:42:44 UTC"
    // after the first replace, which Date.parse rejects.
    const norm = str.replace(' ', 'T').replace(/ ?(?:UTC|GMT)$/i, 'Z');
    const ms = Date.parse(norm);
    return Number.isFinite(ms) ? ms : NaN;
  }
  // Pulse Secure / Ivanti Connect Secure (and similar hand-rolled
  // access log) timestamp: `YYYY-MM-DD--HH-MM-SS` — double-dash
  // between date and time, hyphens as the time separator. Not an
  // ISO form so `Date.parse` would reject it; normalise to the
  // canonical ISO spelling and delegate.
  {
    const m = /^(\d{4})-(\d{2})-(\d{2})--(\d{2})-(\d{2})-(\d{2})$/.exec(str);
    if (m) {
      const y = +m[1], mo = +m[2], d = +m[3];
      const hh = +m[4], mm = +m[5], ss = +m[6];
      if (mo >= 1 && mo <= 12 && d >= 1 && d <= 31
          && hh < 24 && mm < 60 && ss < 60) {
        const ms = Date.UTC(y, mo - 1, d, hh, mm, ss);
        if (Number.isFinite(ms)) return ms;
      }
    }
  }
  // Microsoft .NET JSON dates: /Date(1234567890123)/
  const webJson = /^\/Date\((-?\d+)\)\/$/.exec(str);
  if (webJson) return Number(webJson[1]);
  // YYYY-MM-DD | YYYY/MM/DD | YYYY.MM.DD  (date only)
  let m = /^(\d{4})[-./](\d{1,2})[-./](\d{1,2})$/.exec(str);
  if (m) {
    const y = +m[1], mo = +m[2], d = +m[3];
    if (mo >= 1 && mo <= 12 && d >= 1 && d <= 31) {
      const ms = Date.UTC(y, mo - 1, d);
      if (Number.isFinite(ms)) return ms;
    }
  }
  // YYYY-MM | YYYY/MM | YYYY.MM  (2-digit month, most common format).
  m = /^(\d{4})[-./](\d{2})$/.exec(str);
  if (m) {
    const y = +m[1], mo = +m[2];
    if (mo >= 1 && mo <= 12) return Date.UTC(y, mo - 1, 1);
    // else fall through to decimal-year interpretation below.
  }
  // Decimal-year forms — "1972.06" month-first, "1972.5" month-first,
  // "1972.13" / "1972.500" / "1972.25" fractional-year fallback.
  // Rule (option C): try month-first when the fractional part is ≤ 2
  // digits AND parses to 01..12; otherwise treat as true fractional year.
  m = /^(\d{4})\.(\d+)$/.exec(str);
  if (m) {
    const y = +m[1];
    const fracStr = m[2];
    if (fracStr.length <= 2) {
      const mo = +fracStr;
      if (mo >= 1 && mo <= 12) return Date.UTC(y, mo - 1, 1);
    }
    // Fractional year: year-start + frac × year-length (leap-aware).
    const frac = Number('0.' + fracStr);
    if (Number.isFinite(frac)) {
      const start = Date.UTC(y, 0, 1);
      const end = Date.UTC(y + 1, 0, 1);
      return start + frac * (end - start);
    }
  }
  // YYYYMMDD — 8 compact digits, only when they form a valid Gregorian date.
  if (/^\d{8}$/.test(str)) {
    const y = +str.slice(0, 4), mo = +str.slice(4, 6), d = +str.slice(6, 8);
    if (y >= 1000 && mo >= 1 && mo <= 12 && d >= 1 && d <= 31) {
      return Date.UTC(y, mo - 1, d);
    }
  }
  // YYYY alone (1000..9999).
  if (/^\d{4}$/.test(str)) {
    const y = +str;
    if (y >= 1000 && y <= 9999) return Date.UTC(y, 0, 1);
  }
  // Apache / Nginx CLF: `20/Jun/2012:19:05:12 +0200` (with optional
  // surrounding `[ ]`). The `.log` parse path runs `_tlMergeClfCells`
  // so the bracketed token reaches us as a single cell; the optional
  // brackets here also let extensionless drops where the merge didn't
  // fire (or partial logs without a timezone) still parse.
  const clf = /^\[?(\d{1,2})\/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s+([+-]\d{4}))?\]?$/i.exec(str);
  if (clf) {
    const CLF_M = { jan:0,feb:1,mar:2,apr:3,may:4,jun:5,
                    jul:6,aug:7,sep:8,oct:9,nov:10,dec:11 };
    const d  = +clf[1], mo = CLF_M[clf[2].toLowerCase()], y = +clf[3];
    const hh = +clf[4], mm = +clf[5], ss = +clf[6];
    let clfMs = Date.UTC(y, mo, d, hh, mm, ss);
    if (clf[7]) {
      // Timezone offset is the wallclock displacement from UTC; subtract
      // it to recover the absolute UTC instant the wallclock represents.
      const sign   = clf[7][0] === '-' ? 1 : -1;
      const offMin = (+clf[7].slice(1, 3)) * 60 + (+clf[7].slice(3, 5));
      clfMs += sign * offMin * 60_000;
    }
    return clfMs;
  }
  // Fallback: anything Date.parse() will take (locale / RFC 2822 / etc.)
  const ms = Date.parse(str);
  return Number.isFinite(ms) ? ms : NaN;
}

// ── Fast-path timestamp parsing ────────────────────────────────────────────
// `_tlParseTimestamp` tests up to 10+ regex patterns per call. For bulk
// parsing (500K rows), we sample a handful of rows to identify the
// dominant format, then use a specialised parser that jumps directly to
// the correct branch — eliminating the regex waterfall.
//
// Format tags returned by `_tlDetectTimestampFormat`:
//   'epoch-s'      10-digit epoch seconds
//   'epoch-ms'     13-digit epoch milliseconds
//   'iso'          ISO 8601 datetime with time component
//   'dotnet'       .NET JSON /Date(…)/
//   'date-ymd'     YYYY-MM-DD / YYYY/MM/DD / YYYY.MM.DD (date only)
//   'year-month'   YYYY-MM / YYYY/MM / YYYY.MM (2-digit month)
//   'compact8'     YYYYMMDD
//   'year-only'    YYYY
//   'generic'      mixed / unrecognised — use full _tlParseTimestamp

const _TL_RE_EPOCH_S = /^-?\d{10}$/;
const _TL_RE_EPOCH_MS = /^-?\d{13}$/;
const _TL_RE_ISO = /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/;
const _TL_RE_IVANTI_DASHED = /^\d{4}-\d{2}-\d{2}--\d{2}-\d{2}-\d{2}$/;
const _TL_RE_DOTNET = /^\/Date\((-?\d+)\)\/$/;
const _TL_RE_DATE_YMD = /^(\d{4})[-./](\d{1,2})[-./](\d{1,2})$/;
const _TL_RE_YEAR_MONTH = /^(\d{4})[-./](\d{2})$/;
const _TL_RE_COMPACT8 = /^\d{8}$/;
const _TL_RE_YEAR_ONLY = /^\d{4}$/;

// All timestamp / numeric / stack-cardinality scoring helpers below now
// take a `RowStore` (see `src/row-store.js`) instead of the legacy
// `string[][]`. The store's `getCell(rowIdx, colIdx)` returns `''` for
// nullish cells / OOB indices — same semantics as the prior
// `r ? r[colIdx] : null` defensive lookups, just compressed into a
// single hot-path call. Hot loops sample the column once via `getCell`
// and operate on the returned string; we never call `getRow` here.
function _tlDetectTimestampFormat(store, colIdx, sampleSize) {
  const n = Math.min(store ? store.rowCount : 0, sampleSize || 30);
  const votes = new Map();
  for (let i = 0; i < n; i++) {
    const c = store.getCell(i, colIdx);
    if (c === '') continue;
    const str = c.trim();
    if (!str) continue;
    let tag = 'generic';
    if (_TL_RE_EPOCH_S.test(str)) tag = 'epoch-s';
    else if (_TL_RE_EPOCH_MS.test(str)) tag = 'epoch-ms';
    else if (_TL_RE_ISO.test(str)) tag = 'iso';
    else if (_TL_RE_IVANTI_DASHED.test(str)) tag = 'ivanti-dashed';
    else if (_TL_RE_DOTNET.test(str)) tag = 'dotnet';
    else if (_TL_RE_DATE_YMD.test(str)) tag = 'date-ymd';
    else if (_TL_RE_YEAR_MONTH.test(str)) tag = 'year-month';
    else if (_TL_RE_COMPACT8.test(str)) tag = 'compact8';
    else if (_TL_RE_YEAR_ONLY.test(str)) tag = 'year-only';
    votes.set(tag, (votes.get(tag) || 0) + 1);
  }
  if (!votes.size) return 'generic';
  // Pick the format with the most votes.
  let best = 'generic', bestN = 0;
  for (const [tag, cnt] of votes) {
    if (cnt > bestN) { bestN = cnt; best = tag; }
  }
  return best;
}

// Specialised parser that skips the regex waterfall. Falls back to the
// full `_tlParseTimestamp` for any cell that doesn't match the expected
// format, so mixed-format columns degrade gracefully rather than producing
// NaN for outlier rows.
function _tlParseTimestampFast(s, fmt) {
  if (s == null) return NaN;
  if (typeof s === 'number') return s;
  const str = String(s).trim();
  if (!str) return NaN;
  switch (fmt) {
    case 'epoch-s':
      if (_TL_RE_EPOCH_S.test(str)) return Number(str) * 1000;
      break;
    case 'epoch-ms':
      if (_TL_RE_EPOCH_MS.test(str)) return Number(str);
      break;
    case 'iso': {
      if (_TL_RE_ISO.test(str)) {
        const norm = str.replace(' ', 'T').replace(/ ?(?:UTC|GMT)$/i, 'Z');
        const ms = Date.parse(norm);
        return Number.isFinite(ms) ? ms : NaN;
      }
      break;
    }
    case 'ivanti-dashed': {
      const m = _TL_RE_IVANTI_DASHED.exec(str);
      if (m) {
        const y  = +str.slice(0, 4);
        const mo = +str.slice(5, 7);
        const d  = +str.slice(8, 10);
        const hh = +str.slice(12, 14);
        const mm = +str.slice(15, 17);
        const ss = +str.slice(18, 20);
        if (mo >= 1 && mo <= 12 && d >= 1 && d <= 31
            && hh < 24 && mm < 60 && ss < 60) {
          const ms = Date.UTC(y, mo - 1, d, hh, mm, ss);
          if (Number.isFinite(ms)) return ms;
        }
      }
      break;
    }
    case 'dotnet': {
      const m = _TL_RE_DOTNET.exec(str);
      if (m) return Number(m[1]);
      break;
    }
    case 'date-ymd': {
      const m = _TL_RE_DATE_YMD.exec(str);
      if (m) {
        const y = +m[1], mo = +m[2], d = +m[3];
        if (mo >= 1 && mo <= 12 && d >= 1 && d <= 31) {
          const ms = Date.UTC(y, mo - 1, d);
          if (Number.isFinite(ms)) return ms;
        }
      }
      break;
    }
    case 'year-month': {
      const m = _TL_RE_YEAR_MONTH.exec(str);
      if (m) {
        const y = +m[1], mo = +m[2];
        if (mo >= 1 && mo <= 12) return Date.UTC(y, mo - 1, 1);
      }
      break;
    }
    case 'compact8':
      if (_TL_RE_COMPACT8.test(str)) {
        const y = +str.slice(0, 4), mo = +str.slice(4, 6), d = +str.slice(6, 8);
        if (y >= 1000 && mo >= 1 && mo <= 12 && d >= 1 && d <= 31) {
          return Date.UTC(y, mo - 1, d);
        }
      }
      break;
    case 'year-only':
      if (_TL_RE_YEAR_ONLY.test(str)) {
        const y = +str;
        if (y >= 1000 && y <= 9999) return Date.UTC(y, 0, 1);
      }
      break;
    default:
      return _tlParseTimestamp(s);
  }
  // Format didn't match this particular cell — fall back to full parser.
  return _tlParseTimestamp(s);
}

// Score a column as "mostly plain numbers" (independent of timestamp
// parsing). Used by the auto-detect fallback so that columns like
// `id`, `index`, `period` can drive the timeline axis in numeric mode.
function _tlScoreColumnAsNumber(store, colIdx, sampleMax) {
  const n = Math.min(store ? store.rowCount : 0, sampleMax || 400);
  if (!n) return 0;
  let seen = 0, ok = 0;
  for (let i = 0; i < n; i++) {
    const c = store.getCell(i, colIdx);
    if (c === '') continue;
    seen++;
    const str = c.trim();
    if (/^-?\d+(?:\.\d+)?$/.test(str) && Number.isFinite(+str)) ok++;
  }
  if (!seen) return 0;
  return ok / seen;
}

function _tlScoreColumnAsTimestamp(store, colIdx, sampleMax) {
  const n = Math.min(store ? store.rowCount : 0, sampleMax || 400);
  if (!n) return 0;
  let seen = 0, ok = 0;
  for (let i = 0; i < n; i++) {
    const c = store.getCell(i, colIdx);
    if (c === '') continue;
    seen++;
    if (Number.isFinite(_tlParseTimestamp(c))) ok++;
  }
  if (!seen) return 0;
  return ok / seen;
}

// Header hints for "this is a timestamp-ish column" (time / date / year /
// period / month / …). `year` / `period` / `month` are only timestamp-y
// when their values parse as timestamps via `_tlParseTimestamp` — otherwise
// they still get picked up by the numeric-axis fallback below.
const _TL_HEADER_HINT_RE = /^(?:time|timestamp|date|datetime|ts|created|modified|@timestamp|event[_-]?time|logged|occurred|year|yyyy|period|month)\b/i;

// Header hints for "this is a sequential / ordinal column" that should
// drive a NUMERIC axis (id, index, period number, row number, etc.).
// Only consulted as a fallback in `_tlAutoDetectTimestampCol` when no
// column parses as a timestamp.
const _TL_NUMERIC_AXIS_HINT_RE = /^(?:id|index|idx|period|seq|sequence|order|row|row[_-]?num|n|num|month|year)\b/i;

// Stack-column auto-detect. Best-attempt guess at a column whose values
// form a small, stable set of categorical labels suitable for stacking a
// histogram. Two tiers:
//   Tier 1 — exact (case-insensitive) header match against a curated list
//            of event-categorical field names (EventName, Event, EventID,
//            Outcome, Result, Status, Action, Operation, Category, Type,
//            Kind, Severity, Level, Channel, Provider).
//   Tier 2 — substring hint on the same seeds, for fields like
//            "event_name" / "operationName" / "log_level".
// Both tiers must pass a cardinality gate: 2 ≤ distinct ≤ 40 AND
// distinct/non-empty ≤ 0.5 (on a 2000-row sample), ruling out unique-ish
// columns (ids, timestamps, free-text). The detected timestamp column is
// always skipped. Returns a column index or `null`.
const _TL_STACK_EXACT = new Set([
  'eventname', 'event', 'eventid', 'event id', 'outcome', 'result', 'status',
  'action', 'operation', 'category', 'type', 'kind', 'severity', 'level',
  'channel', 'provider',
]);
const _TL_STACK_HINT_RE = /(eventname|event|outcome|result|status|action|operation|category|type|kind|severity|level|channel|provider)/i;

function _tlScoreStackCardinality(store, colIdx, sampleMax) {
  const n = Math.min(store ? store.rowCount : 0, sampleMax || 2000);
  if (!n) return null;
  const seen = new Set();
  let nonEmpty = 0;
  for (let i = 0; i < n; i++) {
    const c = store.getCell(i, colIdx);
    if (c === '') continue;
    nonEmpty++;
    seen.add(c);
    if (seen.size > 60) return { distinct: seen.size, nonEmpty, tooMany: true };
  }
  return { distinct: seen.size, nonEmpty, tooMany: false };
}

function _tlStackColumnPasses(store, colIdx) {
  const s = _tlScoreStackCardinality(store, colIdx, 2000);
  if (!s || s.tooMany) return false;
  if (s.distinct < 2 || s.distinct > 40) return false;
  if (s.nonEmpty < 10) return false;
  if ((s.distinct / s.nonEmpty) > 0.5) return false;
  return true;
}

function _tlAutoDetectStackCol(columns, store, timeColIdx) {
  if (!columns || !store || !store.rowCount) return null;
  // Tier 1 — exact header match.
  for (let i = 0; i < columns.length; i++) {
    if (i === timeColIdx) continue;
    const name = String(columns[i] || '').trim().toLowerCase();
    if (!name) continue;
    if (_TL_STACK_EXACT.has(name) && _tlStackColumnPasses(store, i)) return i;
  }
  // Tier 2 — substring hint.
  for (let i = 0; i < columns.length; i++) {
    if (i === timeColIdx) continue;
    const name = String(columns[i] || '').trim();
    if (!name) continue;
    if (_TL_STACK_HINT_RE.test(name) && _tlStackColumnPasses(store, i)) return i;
  }
  return null;
}

function _tlAutoDetectTimestampCol(columns, store) {

  // Pass 1 — headers that look timestamp-ish AND parse as timestamps.
  for (let i = 0; i < columns.length; i++) {
    if (_TL_HEADER_HINT_RE.test(String(columns[i] || '').trim())) {
      if (_tlScoreColumnAsTimestamp(store, i, 200) >= 0.5) return i;
    }
  }
  // Pass 2 — any column whose cells overwhelmingly parse as timestamps.
  let best = -1, bestScore = 0.6;
  for (let i = 0; i < columns.length; i++) {
    const s = _tlScoreColumnAsTimestamp(store, i, 200);
    if (s > bestScore) { bestScore = s; best = i; }
  }
  if (best >= 0) return best;

  // Pass 3 — numeric-axis fallback. Prefer columns whose header hints at
  // an ordinal (`id` / `index` / `period` / …) AND whose cells are ≥ 80 %
  // numeric. No hint-only fallback: we don't want to grab random
  // all-numeric columns like "amount" or "latitude" for a file with no
  // real timeline concept — the user can pick those manually.
  for (let i = 0; i < columns.length; i++) {
    const name = String(columns[i] || '').trim();
    if (!_TL_NUMERIC_AXIS_HINT_RE.test(name)) continue;
    if (_tlScoreColumnAsNumber(store, i, 200) >= 0.8) return i;
  }
  return null;
}

// Is a given column best represented as a numeric axis (ordinals, not
// wall-clock times)? Returns true when the cells parse as plain numbers
// but NOT as timestamps.
function _tlColumnIsNumericAxis(store, colIdx) {
  const numScore = _tlScoreColumnAsNumber(store, colIdx, 200);
  if (numScore < 0.8) return false;
  const tsScore = _tlScoreColumnAsTimestamp(store, colIdx, 200);
  // Numeric axis wins unless the column parses as real timestamps
  // appreciably better than as bare numbers (e.g. 4-digit years that
  // would otherwise score 1.0 for both paths stay on the timestamp path).
  return numScore >= tsScore + 0.05;
}


function _tlAutoBucketMs(rangeMs, target) {
  if (!rangeMs || rangeMs <= 0) return 60_000;
  const ideal = rangeMs / (target || TIMELINE_BUCKETS_TARGET);
  for (const opt of TIMELINE_BUCKET_OPTIONS) {
    if (opt.ms == null) continue;
    if (opt.ms >= ideal) return opt.ms;
  }
  return TIMELINE_BUCKET_OPTIONS[TIMELINE_BUCKET_OPTIONS.length - 1].ms;
}

// Numeric-axis auto-bucket. For a range like 0..1000, target 80 buckets →
// ideal step 12.5, round up to a "nice" step from the 1-2-5 ladder (→ 20).
// Returned value is in the axis's native numeric units, NOT ms.
function _tlAutoBucketNumeric(range, target) {
  if (!range || range <= 0 || !Number.isFinite(range)) return 1;
  const ideal = range / (target || TIMELINE_BUCKETS_TARGET);
  if (!Number.isFinite(ideal) || ideal <= 0) return 1;
  const pow = Math.pow(10, Math.floor(Math.log10(ideal)));
  const n = ideal / pow;
  let nice;
  if (n <= 1) nice = 1;
  else if (n <= 2) nice = 2;
  else if (n <= 2.5) nice = 2.5;
  else if (n <= 5) nice = 5;
  else nice = 10;
  return nice * pow;
}

// Compact number formatter for numeric-axis tick labels. Picks decimals
// based on the visible range so tiny sub-unit steps still read cleanly.
function _tlFormatNumericTick(v, range) {
  if (!Number.isFinite(v)) return '';
  const abs = Math.abs(range);
  let digits = 0;
  if (abs > 0 && abs < 10) digits = 2;
  else if (abs < 100) digits = 1;
  if (abs >= 1_000_000) return v.toLocaleString(undefined, { maximumFractionDigits: 0 });
  return v.toLocaleString(undefined, { maximumFractionDigits: digits });
}

// `isNumeric` (optional) switches off the wall-clock date formatting path
// and renders the tick as a bare number with range-aware precision.
function _tlFormatTick(ms, rangeMs, isNumeric) {
  if (!Number.isFinite(ms)) return '';
  if (isNumeric) return _tlFormatNumericTick(ms, rangeMs);
  const d = new Date(ms);
  const pad = n => String(n).padStart(2, '0');
  if (rangeMs < 120_000) return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
  if (rangeMs < 86_400_000) return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
  if (rangeMs < 86_400_000 * 30) return `${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
}

// `isNumeric` (optional) — render the scrubber / tooltip / chip label as a
// locale-aware number instead of a UTC wall-clock timestamp.
function _tlFormatFullUtc(ms, isNumeric) {
  if (!Number.isFinite(ms)) return '—';
  if (isNumeric) return Number(ms).toLocaleString(undefined, { maximumFractionDigits: 4 });
  const d = new Date(ms);
  const pad = n => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

// Human-friendly duration between two epoch-ms values. Picks the two
// largest non-zero units so the readout reads like "30m", "2h 15m",
// "3d 4h", "45s", "1.2s" (sub-second). Used by the active-datetime
// range banner so the analyst sees span at a glance without mental
// subtraction. Returns '' for non-finite spans (numeric-axis mode).
function _tlFormatDuration(ms) {
  if (!Number.isFinite(ms) || ms < 0) return '';
  if (ms < 1000) return ms.toFixed(0) + 'ms';
  const s = ms / 1000;
  if (s < 60) return (s >= 10 ? s.toFixed(0) : s.toFixed(1)) + 's';
  const m = Math.floor(s / 60);
  const secR = Math.round(s - m * 60);
  if (m < 60) return secR ? `${m}m ${secR}s` : `${m}m`;
  const h = Math.floor(m / 60);
  const minR = m - h * 60;
  if (h < 24) return minR ? `${h}h ${minR}m` : `${h}h`;
  const d = Math.floor(h / 24);
  const hR = h - d * 24;
  if (d < 365) return hR ? `${d}d ${hR}h` : `${d}d`;
  const y = Math.floor(d / 365);
  const dR = d - y * 365;
  return dR ? `${y}y ${dR}d` : `${y}y`;
}

// Minimal relative-time grammar: a single integer followed by a unit
// suffix (`s` | `m` | `h` | `d` | `w`). Whitespace around the value is
// tolerated; case is ignored. Returns the duration in milliseconds, or
// `null` if the input doesn't match. Used by the inline datetime range
// widget's "Last <N> <unit>" mode — kept deliberately small so that
// compound terms like `1d 6h` are not silently accepted (they'd require
// a tokeniser; defer to a follow-up if analysts ask for it).
function _tlParseRelative(s) {
  if (s == null) return null;
  const m = String(s).trim().toLowerCase().match(/^(\d+)\s*([smhdw])$/);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  if (!Number.isFinite(n) || n <= 0) return null;
  const unit = m[2];
  const mul = unit === 's' ? 1000
    : unit === 'm' ? 60_000
      : unit === 'h' ? 3_600_000
        : unit === 'd' ? 86_400_000
          : 604_800_000; // 'w'
  return n * mul;
}

// Inverse of `_tlParseRelative`: pick the largest single unit that
// divides `ms` exactly so a 7200000ms span round-trips to "2h" rather
// than "120m". Returns `''` for non-positive / non-finite inputs.
function _tlFormatRelative(ms) {
  if (!Number.isFinite(ms) || ms <= 0) return '';
  const units = [
    [604_800_000, 'w'],
    [86_400_000, 'd'],
    [3_600_000, 'h'],
    [60_000, 'm'],
    [1000, 's'],
  ];
  for (const [size, unit] of units) {
    if (ms % size === 0) return (ms / size) + unit;
  }
  return '';
}

function _tlFormatBytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + ' MB';
  return (n / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

function _tlEsc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Stable per-file key for persisted things like regex extractors / card widths.
function _tlFileKey(file) {
  if (!file) return 'anon';
  return `${file.name || ''}|${file.size || 0}|${file.lastModified || 0}`;
}

// CSV-escape a single cell (RFC 4180-ish).
function _tlCsvCell(s) {
  const str = s == null ? '' : String(s);
  if (/[",\r\n]/.test(str)) return '"' + str.replace(/"/g, '""') + '"';
  return str;
}
function _tlCsvRow(cells) { return cells.map(_tlCsvCell).join(','); }

// Evaluate a JSON path-array against a parsed value. Paths look like
//   ['user', '[2]', 'name'] — bracketed integers select array indices.
function _tlJsonPathGet(value, path) {
  let cur = value;
  for (const seg of path) {
    if (cur == null) return undefined;
    if (/^\[\d+\]$/.test(seg)) {
      const i = Number(seg.slice(1, -1));
      cur = cur[i];
    } else {
      cur = cur[seg];
    }
  }
  return cur;
}

function _tlJsonPathLabel(path) {
  if (!path.length) return '(root)';
  return path.map(s => /^\[\d+\]$/.test(s) ? s : '.' + s).join('').replace(/^\./, '');
}

// Cheap sniff: does this string look like it could be JSON? Used by the
// auto-extract scanner to decide whether to `JSON.parse` a cell.
function _tlMaybeJson(s) {
  if (!s) return false;
  const first = s.charAt(0);
  return first === '{' || first === '[';
}

