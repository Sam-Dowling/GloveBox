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
const TIMELINE_EXTS = new Set(['csv', 'tsv', 'evtx', 'sqlite', 'db', 'log']);

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
const TIMELINE_COL_TOP_N = 500;
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

