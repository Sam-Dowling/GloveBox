'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-parser-helpers.js — shared parser/tokenizer helpers used by
// BOTH the main-thread Timeline route and the off-thread Timeline parse
// worker. Extracted from `src/app/timeline/timeline-helpers.js` and
// `src/workers/timeline-worker-shim.js` so the parser surface (CLF /
// syslog 3164+5424 / JSONL / CloudTrail / CEF / LEEF / logfmt / W3C /
// Apache error log / generic access log / Zeek) lives in exactly one
// place. Previously these were duplicated source-for-source in both
// files with a "Keep in lockstep" comment; the cross-realm parity tests
// in `tests/unit/timeline-worker-shim-parity.test.js` ensured no drift,
// but the source duplication was a maintenance smell.
//
// Load order:
//   - Main bundle: this file BEFORE `src/app/timeline/timeline-helpers.js`
//                  (which depends on these symbols).
//   - Worker bundle: this file is concatenated after
//                    `src/workers/timeline-worker-shim.js` and before
//                    `src/row-store.js` in the timeline parse worker
//                    bundle (see `_timeline_worker_bundle_src` in
//                    `scripts/build.py`).
//
// Pure: no DOM, no app state, no IOC emission, no `pushIOC` calls. Each
// helper takes raw input strings / numbers and returns parsed records.
// Safe to run in either context.
// ════════════════════════════════════════════════════════════════════════════


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



// Three-letter month abbreviation → 0-indexed month.
const _TL_MONTH_ABBR = {
  jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5,
  jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11,
};



// Canonical column order for RFC 3164 syslog. `Timestamp` lives at
// index 0 so `_tlAutoDetectTimestampCol`'s header-hint regex picks it
// up; `Severity` at index 1 makes it the default stack column via
// `_tlAutoDetectStackCol` (it's in the `_TL_STACK_EXACT` whitelist).
const _TL_SYSLOG3164_COLS = ['Timestamp', 'Severity', 'Facility', 'Host',
                             'Program', 'PID', 'Message'];



// Canonical column order for RFC 5424 syslog. `Timestamp` at index 0
// (header-hint regex picks it up); `Severity` at index 1 (default
// stack column).
const _TL_SYSLOG5424_COLS = ['Timestamp', 'Severity', 'Facility', 'Host',
                             'App', 'ProcID', 'MsgID', 'StructuredData',
                             'Message'];


const _TL_SYSLOG_FACILITY = [
  'kern', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news',
  'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'audit', 'alert', 'clock',
  'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7',
];



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


function _tlSyslogFacilityName(fac) {
  return _TL_SYSLOG_FACILITY[fac | 0] || ('facility' + (fac | 0));
}



function _tlSyslogSeverityName(sev) {
  return _TL_SYSLOG_SEVERITY[sev | 0] || '';
}

