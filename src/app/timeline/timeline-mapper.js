'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-mapper.js — per-format canonical column mappers + column fusion
// predicate for merged Timelines.
//
// When a Timeline view hosts ≥2 sources, the composite RowStore prepends
// the `TIMELINE_CANONICAL_COLS` (`__source`, `__format`, `Timestamp`,
// `Host`, `User`, `EventID`, `Severity`, `Category`, `SourceIP`,
// `DestIP`) so queries / top-values / pivots / detections see a uniform
// schema regardless of the file's native columns. This file owns the
// projection from each source's native row shape into those canonical
// cells.
//
// The canonical schema is intentionally narrow — every entry holds
// short identifier-shape values (filenames, hostnames, usernames, event
// IDs, severities, IPs). Wide-narrative columns (process command lines,
// full message bodies, user-agent strings, EVTX Event Data blobs) are
// NOT projected into canonical slots. They live on each source's
// native column plane where the original column name preserves the
// semantic. Three reasons:
//   1. Multi-KB blobs would balloon the composite store, slow
//      top-values sweeps (O(rows×cols)), and saturate the
//      row-search-text cache.
//   2. Forcing every shape through one synthetic column produces
//      misclassifications (e.g. a CSV's `userAgent` column being
//      pulled into a canonical `Process` slot — UA strings aren't
//      processes).
//   3. The cross-source pivot affordance is preserved by the auto-
//      extract pump's KV-field pass, which surfaces the same fields
//      as named virtual columns (e.g. EVTX `TargetUserName` /
//      `Image`) the analyst can pivot on by name.
//
// ─── MAPPER API ───────────────────────────────────────────────────────────
// Each entry in `TIMELINE_MAPPERS` is a function:
//
//   canonicalFor(source, baseCellArr) → { [canonicalCol]: string }
//
// where `source` is the SourceRecord shape (see timeline-sources.js) and
// `baseCellArr` is the native row as a `string[]` of length
// `source.baseColumns.length`. The function returns a plain object
// keyed by canonical column name; only canonical cells for which the
// mapper can resolve a value are present. The composite builder
// substitutes an empty string for missing cells.
//
// Mappers MUST be pure, allocation-light, and never mutate
// `baseCellArr`. Column-index lookups cache via `source._colIdxCache`
// (a Map populated lazily) so repeated reads don't pay an
// `Array.indexOf` per cell.
//
// ─── FUSION PREDICATE ─────────────────────────────────────────────────────
// `timelineColumnsCanFuse(a, b)` decides whether two native columns
// sharing a (case-insensitive) name should collapse to a single column
// in the composite schema or coexist as namespaced siblings
// (`<sourceLabel>·<col>`). Rules:
//
//   1. Names match case-insensitively after trimming.
//   2. Format-kind compatibility: same formatKind OR at least one side
//      is user-defined tabular (`csv`/`tsv`/`log` — which have no
//      schema semantics beyond the header). Two EVTX files with a
//      coincidentally identical extension column fuse; an EVTX
//      `EventID` column never fuses with a CSV column named `EventID`
//      unless the CSV side is the user-defined one.
//   3. Content-compatibility probe: a small sample (up to 200 values)
//      from each side must pass the same detector (all-empty ignored,
//      both IPv4 → OK, both pure numeric → OK, both string-ish → OK;
//      one numeric + one text → NOT OK to avoid silent corruption).
//
// The predicate is pure. Callers hold onto its result — the composite
// builder invokes it once per candidate pair during schema resolution.
//
// ─── WHY THIS LIVES IN ITS OWN FILE ───────────────────────────────────────
// `timeline-helpers.js` already hosts per-format tokenisers / schema
// arrays (`_TL_SYSLOG3164_COLS`, `_TL_CLF_COMBINED_COLS`, ...). Those
// are data; mappers are code that reads the data. Keeping them
// separate means a new format adds: (a) its tokeniser + column list
// in `timeline-parser-helpers.js`, (b) a mapper entry here. Two
// touchpoints, not a scattered rewrite.
//
// Loads AFTER `timeline-parser-helpers.js` (uses the column-name
// schemas), AFTER `src/constants.js` (uses `TIMELINE_CANONICAL_COLS`,
// `TIMELINE_MERGE_ELIGIBLE_KINDS`), and BEFORE `timeline-composite.js`
// (which drives the mapper).
//
// NOT in the worker bundle — mapping runs main-thread only, post-parse.
// ════════════════════════════════════════════════════════════════════════════

// ── Column-index cache ──────────────────────────────────────────────────────
// `source._colIdxCache` is a Map<lowercaseName, int>. Built lazily on
// first lookup and reused for every row in that source. Keys are
// lowercase because mapper lookups ("computer" / "Computer" /
// "COMPUTER") all resolve to the same index.
function _tlmCol(source, name) {
  if (!source._colIdxCache) {
    const m = new Map();
    const cols = source.baseColumns || [];
    for (let i = 0; i < cols.length; i++) {
      const k = String(cols[i] || '').toLowerCase();
      if (!m.has(k)) m.set(k, i);
    }
    source._colIdxCache = m;
  }
  const idx = source._colIdxCache.get(String(name || '').toLowerCase());
  return idx == null ? -1 : idx;
}

// Return the first non-empty `baseCellArr` cell matching any of the
// supplied (case-insensitive) candidate column names. Used by CSV /
// TSV mappers where column naming is user-defined and we probe by
// convention (`host`, `hostname`, `computer`, ...).
function _tlmFirst(source, baseCellArr, names) {
  for (let i = 0; i < names.length; i++) {
    const idx = _tlmCol(source, names[i]);
    if (idx >= 0) {
      const v = baseCellArr[idx];
      if (v != null && v !== '') return String(v);
    }
  }
  return '';
}

// ── Per-format mappers ──────────────────────────────────────────────────────
//
// Each mapper returns an object keyed by canonical column name; only
// present keys are copied into the composite row. Missing keys → empty
// string in the composite.
//
// `source.sourceLabel` / `source.formatLabel` are injected as
// `__source` / `__format` uniformly for every format by the composite
// builder — mappers don't repeat that work.

const TIMELINE_MAPPERS = {

  // ── CSV / TSV / log / generic access-log ─────────────────────────────
  // User-defined schema. We probe column names by convention:
  // `host|hostname|computer|machine` → Host, `user|username|account` →
  // User, `src_ip|source_ip|client_ip|ip|c-ip` → SourceIP, etc. The
  // search is cheap (one Map lookup per candidate, cached per source)
  // and wrong-column pulls gracefully surface as empty canonical cells
  // rather than silent misclassification — users can still pivot on
  // the native columns by name.
  //
  // EDR / endpoint-export aliases: the probe lists below also recognise
  // the column-name conventions used by CrowdStrike Falcon (`aid`,
  // `ComputerName`, `event_simpleName`, `LocalAddressIP4`,
  // `RemoteAddressIP4`), Microsoft Defender for Endpoint / Advanced
  // Hunting (`DeviceName`, `ActionType`, `AccountName`, `RemoteIP`),
  // SentinelOne Deep Visibility (dotted `agent.name`, `event.type`,
  // `src.ip.address`, `dst.ip.address`, `src.process.user`), Cortex
  // XDR (`_time`, `agent_hostname`, `event_type`, `action_local_ip`,
  // `action_remote_ip`), and Elastic ECS (`@timestamp`, `host.name`,
  // `user.name`, `event.action`, `event.category`, `source.ip`,
  // `destination.ip`). Probe order is specific-before-generic so a
  // vendor-specific alias never gets shadowed by a coincidental match
  // earlier in the list (e.g. `device_name` before `name`-shaped
  // generics).
  //
  // Wide-narrative columns (`message` / `body` / `description` /
  // process command lines like `ProcessCommandLine` /
  // `process.command_line` / `actor_process_command_line`) are
  // intentionally NOT projected into canonical slots: the canonical
  // schema (see `TIMELINE_CANONICAL_COLS`) is for short identifier-
  // shape values that justify cross-source pivots. Long-form text
  // stays on the source's native column where the original header
  // preserves the semantic, preventing multi-KB blobs from being
  // duplicated row-for-row in a synthetic column and avoiding the
  // "useragent shows up under Process" misclassification that comes
  // from forcing every shape through a one-size-fits-all schema.
  csv: (source, row) => {
    const out = {};
    // Timestamp probe. EDR-additive: `_time` (Cortex XDR),
    // `device_timestamp` (CBC + some Falcon), `event_timestamp`,
    // `agent_time`. ECS `@timestamp` already covered.
    const ts = _tlmFirst(source, row, [
      'timestamp', 'time', '@timestamp', 'datetime', 'date',
      'creationtime', 'eventtime', 'published',
      '_time', 'device_timestamp', 'event_timestamp', 'agent_time',
    ]);
    if (ts) out.Timestamp = ts;
    // Host probe. EDR-additive: `device_name` (MDE / CBC),
    // `agent_hostname` (Cortex), `agent.name` / `agent.hostname` (S1),
    // `host.name` (ECS), `endpoint.name`. `devicename` /
    // `computername` already covered.
    const host = _tlmFirst(source, row, [
      'host', 'hostname', 'computer', 'computername', 'devicename',
      'machine', 'server', 's-computername',
      'device_name', 'agent_hostname', 'agent.name', 'agent.hostname',
      'host.name', 'endpoint.name',
    ]);
    if (host) out.Host = host;
    // User-surrogate probe list. `userid` / `principal` / `upn` / `actor`
    // / `alternateid` / `email` cover M365 audit, Okta system log,
    // Salesforce audit trail, and generic SIEM shapes.
    //
    // EDR-additive: `accountname` (MDE), `account_name`, `user.name`
    // (ECS), `process_username` (CBC), `actor_user`,
    // `src.process.user.name` (S1), `src.process.user` (S1 alt),
    // `initiatingprocessaccountname` (MDE — distinct from
    // `accountname` so cross-vendor merges where MDE rows carry both
    // resolve to the simpler `accountname` first).
    const user = _tlmFirst(source, row, [
      'user', 'username', 'userid', 'user_id', 'account', 'user_name',
      'cs-username', 'suser', 'principal', 'actor', 'upn', 'email',
      'displayname', 'alternateid',
      'accountname', 'account_name', 'user.name',
      'process_username', 'actor_user',
      'src.process.user.name', 'src.process.user',
      'initiatingprocessaccountname',
    ]);
    if (user) out.User = user;
    // EventID-surrogate probe list. `eventname` / `operation` / `action`
    // / `verb` / `activity` catch M365, AWS CloudTrail (as CSV export),
    // Salesforce, and generic action-log CSVs where the event
    // identifier is a short verb rather than a numeric id.
    //
    // EDR-additive: `actiontype` / `action_type` (MDE — primary action
    // discriminator, e.g. `ProcessCreated` / `FileCreated`),
    // `event_simplename` (Falcon — case-insensitive match covers the
    // canonical `event_simpleName`), `event.action` (ECS), `event.type`
    // (S1, ECS).
    const eid = _tlmFirst(source, row, [
      'eventid', 'event_id', 'event id', 'signatureid', 'event_type',
      'eventname', 'event_name', 'operation', 'action', 'verb',
      'activity', 'eventtype',
      'actiontype', 'action_type', 'event_simplename',
      'event.action', 'event.type',
    ]);
    if (eid) out.EventID = eid;
    // Severity-surrogate probe list. `outcome` / `result` / `status`
    // / `resultstatus` catch M365 audit, Salesforce, and generic
    // success/failure log shapes where the "severity" is really the
    // outcome of the action.
    //
    // EDR-additive: `event.severity` (ECS), `alert_severity` (Cortex /
    // various), `threat.severity` (Defender alerts).
    const sev = _tlmFirst(source, row, [
      'severity', 'level', 'priority', 'loglevel',
      'outcome', 'result', 'status', 'resultstatus',
      'event.severity', 'alert_severity', 'threat.severity',
    ]);
    if (sev) out.Severity = sev;
    // Category-surrogate probe list. `workload` / `recordtype`
    // / `service` / `application` catch M365 audit (Workload tells you
    // SharePoint vs AzureAD vs Exchange), AWS service names, and
    // generic service-tier logs.
    //
    // EDR-additive: `event.category` (ECS), `event.kind` (ECS),
    // `event_category`.
    const cat = _tlmFirst(source, row, [
      'category', 'channel', 'facility', 'source', 'component', 'module',
      'workload', 'recordtype', 'record_type', 'service', 'application',
      'event.category', 'event.kind', 'event_category',
    ]);
    if (cat) out.Category = cat;
    // SourceIP probe. EDR-additive: `source.ip` (ECS),
    // `src.ip.address` (S1), `localaddressip4` (Falcon — agent-
    // perspective: local end of a network connection IS the source),
    // `local_ip`, `action_local_ip` (Cortex).
    const sip = _tlmFirst(source, row, [
      'src_ip', 'source_ip', 'client_ip', 'clientip', 'srcip', 'sourceip',
      'src', 'c-ip', 'client', 'ip',
      'source.ip', 'src.ip.address',
      'localaddressip4', 'local_ip', 'action_local_ip',
    ]);
    if (sip) out.SourceIP = sip;
    // DestIP probe. EDR-additive: `destination.ip` (ECS),
    // `dst.ip.address` (S1), `remoteaddressip4` (Falcon), `remoteip`
    // (MDE — the column is literally `RemoteIP`), `remote_ip`,
    // `action_remote_ip` (Cortex).
    const dip = _tlmFirst(source, row, [
      'dst_ip', 'dest_ip', 'destination_ip', 'dstip', 'destip', 'dst',
      's-ip', 'server_ip', 'targetip', 'target_ip', 'dstaddr', 'destaddr',
      'destination.ip', 'dst.ip.address',
      'remoteaddressip4', 'remoteip', 'remote_ip', 'action_remote_ip',
    ]);
    if (dip) out.DestIP = dip;
    return out;
  },

  // ── Apache / Nginx CLF (`.log` with 7 or 9 columns) ──────────────────
  // Fixed schema: `ip ident auth time request status bytes [referer user_agent]`.
  // Columns (indices into the canonical 9-col list):
  //    0 ip       → SourceIP
  //    3 time     → Timestamp (CLF bracketed form)
  //    5 status   → Severity (2xx/3xx/4xx/5xx category)
  //    2 auth     → User (Apache `%u` — authenticated user when present)
  //
  // The `request` field (`row[4]`, "GET /x HTTP/1.1") and the
  // `user_agent` field (`row[8]` when present) stay on the source's
  // native columns — they're long-form text that doesn't belong in the
  // canonical cross-source pivot schema.
  'log': (source, row) => {
    const out = {};
    if (row[0]) out.SourceIP = String(row[0]);
    if (row[3]) out.Timestamp = String(row[3]);
    if (row[5]) out.Severity = String(row[5]);
    const auth = row[2];
    if (auth && auth !== '-') out.User = String(auth);
    out.Category = 'access';
    return out;
  },

  // ── EVTX (Windows Event Log — canonical schema fixed by parser) ──────
  // Columns: `Timestamp, Event ID, Level, Provider, Channel, Computer, Event Data`.
  //
  // The Event Data blob (`row[6]`) carries multi-KB rendered XML / KV
  // text per row. We deliberately do NOT project it into a canonical
  // column — duplicating it would balloon the composite store, slow
  // top-values sweeps, and saturate the row-search-text cache. The
  // blob stays on its native `Event Data` column where the analyst can
  // open the row drawer to read it.
  //
  // Forensically-important fields inside the blob (`TargetUserName`,
  // `SubjectUserName`, `Image`, `NewProcessName`, `LogonType`, …) are
  // surfaced as virtual columns by the auto-extract pump's KV-field
  // pass (~60 ms post-mount, gated on `TIMELINE_FORENSIC_EVTX_FIELDS_SET`)
  // rather than mined eagerly here — the auto-extract path produces
  // visible columns the analyst can pivot on by name, which is the
  // same affordance the eager regex used to provide.
  evtx: (source, row) => {
    const out = {};
    if (row[0]) out.Timestamp = String(row[0]);
    if (row[1]) out.EventID   = String(row[1]);
    if (row[2]) out.Severity  = String(row[2]);
    if (row[3] || row[4]) {
      // Category = `<Channel> / <Provider>` when both present, else
      // whichever single one is. This lets `category:System` queries
      // match the System channel across merged files.
      const ch = row[4] ? String(row[4]) : '';
      const pr = row[3] ? String(row[3]) : '';
      out.Category = ch && pr ? (ch + ' / ' + pr) : (ch || pr);
    }
    if (row[5]) out.Host = String(row[5]);
    return out;
  },

  // ── Syslog RFC 3164 ──────────────────────────────────────────────────
  // Columns: `Timestamp, Severity, Facility, Host, Program, PID, Message`.
  // The native `Program` (`row[4]`) and `Message` (`row[6]`) columns
  // stay on the source's native plane — analysts pivot on them by
  // name. The canonical schema is for short identifier-shape values.
  syslog3164: (source, row) => {
    const out = {};
    if (row[0]) out.Timestamp = String(row[0]);
    if (row[1]) out.Severity  = String(row[1]);
    if (row[2]) out.Category  = String(row[2]);
    if (row[3]) out.Host      = String(row[3]);
    return out;
  },

  // ── Syslog RFC 5424 ──────────────────────────────────────────────────
  // Columns: `Timestamp, Severity, Facility, Host, App, ProcID, MsgID,
  //           StructuredData, Message`.
  // The native `App` / `Message` / `StructuredData` columns stay on
  // the source's native plane. `MsgID` is a short identifier so it
  // earns its slot as canonical `EventID`.
  syslog5424: (source, row) => {
    const out = {};
    if (row[0]) out.Timestamp = String(row[0]);
    if (row[1]) out.Severity  = String(row[1]);
    if (row[2]) out.Category  = String(row[2]);
    if (row[3]) out.Host      = String(row[3]);
    if (row[6]) out.EventID   = String(row[6]);
    return out;
  },

  // ── Zeek (dynamic schema) ────────────────────────────────────────────
  // The tokeniser locks columns from the `#fields` directive. Every
  // connection-log has `ts`, `id.orig_h`, `id.resp_h`; NIDS logs add
  // `src`, `dst`; DNS logs add `query`. Use the CSV-style probe since
  // the column names vary between log types.
  zeek: (source, row) => {
    const out = {};
    const ts = _tlmFirst(source, row, ['ts', 'time', 'timestamp']);
    if (ts) out.Timestamp = ts;
    const sip = _tlmFirst(source, row, ['id.orig_h', 'orig_h', 'src', 'src_ip']);
    if (sip) out.SourceIP = sip;
    const dip = _tlmFirst(source, row, ['id.resp_h', 'resp_h', 'dst', 'dst_ip']);
    if (dip) out.DestIP = dip;
    const host = _tlmFirst(source, row, ['host', 'server_name', 'query']);
    if (host) out.Host = host;
    // User probe — Zeek's `user` field is a real username (FTP / SMB
    // auth, HTTP basic-auth). The `user_agent` column is intentionally
    // NOT probed here: UA strings are not user identifiers and stay
    // on the native `user_agent` column where their semantic is
    // preserved.
    const user = _tlmFirst(source, row, ['user', 'username']);
    if (user) out.User = user;
    // Zeek tokeniser stamps `#path` as the format label; we also
    // project it into Category so users can `category:http` /
    // `category:dns` across merged Zeek logs.
    if (source._zeekPath) out.Category = source._zeekPath;
    return out;
  },

  // ── JSONL (generic) ──────────────────────────────────────────────────
  // Schema varies wildly between producers (CloudTrail, K8s, Vector).
  // Use the same CSV-style probe as CSV — JSONL tokeniser produces
  // dotted-path column names, which we match case-insensitively.
  jsonl: (source, row) => TIMELINE_MAPPERS.csv(source, row),

  // ── AWS CloudTrail (JSONL with canonical column projection) ──────────
  // Columns start with `eventTime, eventName, eventSource, awsRegion,
  // sourceIPAddress, userIdentity.type, userIdentity.userName,
  // userIdentity.arn, userIdentity.accountId, userAgent, eventID,
  // eventType, recipientAccountId, requestID, errorCode, errorMessage,
  // readOnly, managementEvent` (plus any source-supplied extras).
  //
  // The native `userAgent`, `errorMessage`, and `errorCode` columns
  // stay on the source's native plane — UA strings aren't process
  // identifiers, and error narratives are long-form text.
  cloudtrail: (source, row) => {
    const out = {};
    const ts = _tlmFirst(source, row, ['eventtime']);
    if (ts) out.Timestamp = ts;
    const name = _tlmFirst(source, row, ['eventname']);
    if (name) out.EventID = name;
    const src = _tlmFirst(source, row, ['eventsource']);
    if (src) out.Category = src;
    const sip = _tlmFirst(source, row, ['sourceipaddress']);
    if (sip) out.SourceIP = sip;
    const user = _tlmFirst(source, row, ['useridentity.username', 'useridentity.arn']);
    if (user) out.User = user;
    return out;
  },

  // ── CEF (Common Event Format) ────────────────────────────────────────
  // Header columns: `Version, Vendor, Product, ProductVersion,
  // SignatureID, Name, Severity` plus dynamic `key=value` extensions.
  // Native columns (`Name`, `msg`, `sproc`/`dproc`) stay on the source
  // plane — they're either long-form text or already named clearly.
  cef: (source, row) => {
    const out = {};
    if (row[4]) out.EventID  = String(row[4]);   // SignatureID
    if (row[6]) out.Severity = String(row[6]);
    const vendor = row[1] ? String(row[1]) : '';
    const product = row[2] ? String(row[2]) : '';
    if (vendor || product) out.Category = (vendor + ' / ' + product).replace(/^\s*\/\s*|\s*\/\s*$/g, '');
    const host = _tlmFirst(source, row, ['shost', 'dhost', 'dvchost']);
    if (host) out.Host = host;
    const user = _tlmFirst(source, row, ['suser', 'duser']);
    if (user) out.User = user;
    const sip = _tlmFirst(source, row, ['src']);
    if (sip) out.SourceIP = sip;
    const dip = _tlmFirst(source, row, ['dst']);
    if (dip) out.DestIP = dip;
    // CEF may not carry an explicit Timestamp field in its header —
    // the wall-clock is usually in the syslog wrapper. The tokeniser
    // materialises it into a `Timestamp` column when present; probe
    // that.
    const ts = _tlmFirst(source, row, ['timestamp', 'rt', 'deviceReceiptTime']);
    if (ts) out.Timestamp = ts;
    return out;
  },

  // ── LEEF (Log Event Extended Format — QRadar) ────────────────────────
  // Native `msg` extension stays on the source's native plane.
  leef: (source, row) => {
    // LEEF is structurally similar to CEF: a fixed header (Version,
    // Vendor, Product, ProductVersion, EventID) + `key=value` ext.
    const out = {};
    if (row[4]) out.EventID = String(row[4]);
    const vendor = row[1] ? String(row[1]) : '';
    const product = row[2] ? String(row[2]) : '';
    if (vendor || product) out.Category = (vendor + ' / ' + product).replace(/^\s*\/\s*|\s*\/\s*$/g, '');
    const host = _tlmFirst(source, row, ['devtime', 'srcHost', 'identhostname', 'host', 'shost', 'dhost']);
    if (host) out.Host = host;
    const user = _tlmFirst(source, row, ['usrname', 'suser', 'duser', 'user']);
    if (user) out.User = user;
    const sip = _tlmFirst(source, row, ['src']);
    if (sip) out.SourceIP = sip;
    const dip = _tlmFirst(source, row, ['dst']);
    if (dip) out.DestIP = dip;
    const sev = _tlmFirst(source, row, ['sev', 'severity']);
    if (sev) out.Severity = sev;
    const ts = _tlmFirst(source, row, ['devtime', 'timestamp']);
    if (ts) out.Timestamp = ts;
    return out;
  },

  // ── logfmt ───────────────────────────────────────────────────────────
  // Native `msg` / `message` / `event` columns stay on the source plane.
  logfmt: (source, row) => {
    const out = {};
    const ts = _tlmFirst(source, row, ['ts', 'timestamp', 'time', '@timestamp']);
    if (ts) out.Timestamp = ts;
    const host = _tlmFirst(source, row, ['host', 'hostname', 'server']);
    if (host) out.Host = host;
    const user = _tlmFirst(source, row, ['user', 'username', 'uid']);
    if (user) out.User = user;
    const sev = _tlmFirst(source, row, ['level', 'severity', 'priority']);
    if (sev) out.Severity = sev;
    const cat = _tlmFirst(source, row, ['component', 'service', 'module', 'app']);
    if (cat) out.Category = cat;
    const sip = _tlmFirst(source, row, ['src_ip', 'client_ip', 'ip']);
    if (sip) out.SourceIP = sip;
    return out;
  },

  // ── W3C Extended Log Format (IIS, AWS ELB/ALB/CloudFront) ────────────
  // Native `cs-method` / `cs-uri-stem` / `request_method` / `request_url`
  // columns stay on the source plane — long-form text doesn't belong
  // in the canonical pivot schema.
  w3c: (source, row) => {
    // Column names are dictated by the `#Fields:` directive. When the
    // log emits split `date` + `time` columns (the IIS default),
    // prefer the concatenated form — a lone date cell with `00:00:00`
    // time reads as the start-of-day midnight which is misleading.
    const out = {};
    const d = _tlmFirst(source, row, ['date']);
    const t = _tlmFirst(source, row, ['time']);
    if (d && t) out.Timestamp = d + ' ' + t;
    else {
      const ts = _tlmFirst(source, row, ['datetime', 'timestamp', '@timestamp']);
      if (ts) out.Timestamp = ts;
      else if (d) out.Timestamp = d;
      else if (t) out.Timestamp = t;
    }
    const host = _tlmFirst(source, row, ['s-computername', 'server_name']);
    if (host) out.Host = host;
    const user = _tlmFirst(source, row, ['cs-username']);
    if (user && user !== '-') out.User = user;
    const sip = _tlmFirst(source, row, ['c-ip', 'client_ip', 'x-forwarded-for']);
    if (sip) out.SourceIP = sip;
    const dip = _tlmFirst(source, row, ['s-ip', 'server_ip']);
    if (dip) out.DestIP = dip;
    const status = _tlmFirst(source, row, ['sc-status', 'elb_status_code', 'http_status']);
    if (status) out.Severity = status;
    out.Category = 'access';
    return out;
  },

  // ── Apache error_log ─────────────────────────────────────────────────
  'apache-error': (source, row) => {
    // Columns: Timestamp, Module, Severity, PID, TID, Client, ErrorCode, Message.
    // The native `Message` (`row[7]`) column stays on the source plane
    // — it's the long-form error narrative.
    const out = {};
    if (row[0]) out.Timestamp = String(row[0]);
    if (row[1]) out.Category  = String(row[1]);
    if (row[2]) out.Severity  = String(row[2]);
    if (row[5]) out.SourceIP  = String(row[5]);
    if (row[6]) out.EventID   = String(row[6]);
    return out;
  },

  // ── Generic access-log (timestamp-led space-delimited) ───────────────
  'access-log': (source, row) => {
    // Dynamic schema with heuristic column naming; fall through to the
    // CSV-style probe because column names aren't guaranteed.
    return TIMELINE_MAPPERS.csv(source, row);
  },
};

// Alias `tsv` → `csv` — the parser treats them identically (only the
// delimiter differs). Keeping both lookup keys lets callers pass the
// raw `formatKind` without a pre-normalisation step.
TIMELINE_MAPPERS.tsv = TIMELINE_MAPPERS.csv;

// Resolve a mapper for a `formatKind`. Returns the CSV-style fallback
// for unknown kinds so a new format added to `timeline-router.js` that
// forgets its mapper entry here still projects something into the
// canonical cells (namely, whatever CSV-style header-name probe
// returns). Emit a one-time console warning so the gap surfaces in dev.
function timelineMapperFor(formatKind) {
  const m = TIMELINE_MAPPERS[formatKind];
  if (m) return m;
  if (!timelineMapperFor._warned) timelineMapperFor._warned = new Set();
  if (!timelineMapperFor._warned.has(formatKind)) {
    timelineMapperFor._warned.add(formatKind);
    try {
      console.warn('[timeline-mapper] no mapper for formatKind=' +
        formatKind + '; falling back to CSV-style name probe');
    } catch (_) { /* console may be absent in unit-test shims */ }
  }
  return TIMELINE_MAPPERS.csv;
}

// ── Fusion predicate ───────────────────────────────────────────────────────

// Classify a column's content-shape from a sample of up to N values.
// Returns one of: 'empty', 'ipv4', 'numeric', 'text'. Used only inside
// `timelineColumnsCanFuse` — pure, no side effects.
//
// /* safeRegex: literal short pattern */
const _TL_MAPPER_IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
// /* safeRegex: literal short pattern */
const _TL_MAPPER_NUMERIC_RE = /^-?\d+(?:\.\d+)?$/;

function _tlmClassify(sampleStrings) {
  let seen = 0, ipv4 = 0, numeric = 0;
  for (let i = 0; i < sampleStrings.length; i++) {
    const v = sampleStrings[i];
    if (v == null || v === '') continue;
    const s = String(v).trim();
    if (!s) continue;
    seen++;
    if (_TL_MAPPER_IPV4_RE.test(s)) ipv4++;
    else if (_TL_MAPPER_NUMERIC_RE.test(s)) numeric++;
  }
  if (seen === 0) return 'empty';
  if (ipv4 / seen >= 0.8) return 'ipv4';
  if (numeric / seen >= 0.8) return 'numeric';
  return 'text';
}

// User-supplied tabular formats — columns are whatever the header says.
// These fuse liberally with any format so analysts pivoting across a
// CSV of their own making plus an EVTX / syslog aren't stuck with
// namespacing noise when the column name happens to match.
const _TL_MAPPER_USER_TABULAR_KINDS = new Set(['csv', 'tsv', 'log', 'access-log']);

// Public: decide whether two same-named native columns from different
// sources should fuse into a single composite column. Returns `true`
// iff all three gates pass.
//
//   @param a - { formatKind, name, samples: string[] }
//   @param b - { formatKind, name, samples: string[] }
function timelineColumnsCanFuse(a, b) {
  if (!a || !b) return false;
  const an = String(a.name || '').trim().toLowerCase();
  const bn = String(b.name || '').trim().toLowerCase();
  if (!an || an !== bn) return false;
  const akind = a.formatKind || '';
  const bkind = b.formatKind || '';
  // Gate 2 — format-kind compatibility.
  const sameFormat = akind === bkind;
  const userTabular = _TL_MAPPER_USER_TABULAR_KINDS.has(akind)
    || _TL_MAPPER_USER_TABULAR_KINDS.has(bkind);
  if (!sameFormat && !userTabular) return false;
  // Gate 3 — content-compat probe.
  const ka = _tlmClassify(a.samples || []);
  const kb = _tlmClassify(b.samples || []);
  if (ka === 'empty' || kb === 'empty') return true;   // fuse — one is empty, nothing to conflict
  return ka === kb;
}

// Expose on the global so unit tests (loaded via `loadModules`) and the
// composite builder can reach them. Pure functions — the globals are
// not stateful beyond the per-source `_colIdxCache` attached to source
// records, which is short-lived (destroyed with the source record).
if (typeof window !== 'undefined') {
  window.TIMELINE_MAPPERS = TIMELINE_MAPPERS;
  window.timelineMapperFor = timelineMapperFor;
  window.timelineColumnsCanFuse = timelineColumnsCanFuse;
}
