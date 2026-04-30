'use strict';
// ════════════════════════════════════════════════════════════════════════════
// xlsx-extras.js — Post-OoxmlRel scanners that target XLSX-only attack
// surfaces not reachable through `_rels/*.rels`:
//
//   1. xl/connections.xml — external data connections (OLEDB / ODBC / web /
//      text). Used for T1567 (data exfil), T1071 (C2 over HTTP/SMB), and
//      "Excel as live-loading dropper" patterns. The connection string and
//      the optional `odcFile` reference can both target attacker
//      infrastructure, and connections marked `refreshOnLoad="1"` execute
//      the moment the workbook opens (no macro warning).
//
//   2. DataMashup (Power Query) — an embedded base64-zipped M-language
//      script stored either inline in `xl/customXml/item*.xml` as a
//      `<DataMashup>` element OR as a `customXml/item*.xml` inside its own
//      `Section1.m` part (Power Query "Section1.m" workbook part). M code
//      can call `Web.Contents`, `File.Contents`, `OleDb.DataSource`, etc.,
//      and Excel auto-refresh ("Refresh data when opening the file") runs
//      it without macro consent. Reference: PolarisSec
//      "Power Query: A New PowerShell" / Lukas Kupczyk research.
//
// Both scanners return array-of-{type,url,severity,note} matching the
// shape XlsxRenderer already pushes into `findings.externalRefs`.
// Used by: XlsxRenderer
// Depends on: JSZip (vendor), DOMParser (host), IOC (constants.js)
// ════════════════════════════════════════════════════════════════════════════

class XlsxConnectionsScanner {
  // Severity floors per connection-type DTLO numeric code in <connection type="...">.
  // 1=ODBC 2=DAO 3=??/file 4=OLEDB 5=Web 6=Text 7=ADO 8=DSP. We don't gate on these
  // — used only as part of the human note. The attacker-controlled URL/UNC in the
  // connection string is what drives severity, via the same _classifyTarget logic
  // OoxmlRelScanner uses. We re-implement it lightly here to avoid crossing files.

  /**
   * Scan a JSZip instance for xl/connections.xml entries.
   * @param {JSZip} zip
   * @returns {Promise<Array<{type:string,url:string,severity:string,note:string}>>}
   */
  static async scan(zip) {
    const out = [];
    const entry = zip.file('xl/connections.xml');
    if (!entry) return out;
    let text;
    try { text = await entry.async('string'); } catch (e) { return out; }
    let dom;
    try { dom = new DOMParser().parseFromString(text, 'text/xml'); }
    catch (e) { return out; }
    if (dom.getElementsByTagName('parsererror').length) return out;

    const conns = dom.getElementsByTagName('connection');
    for (const c of Array.from(conns)) {
      const name = c.getAttribute('name') || '?';
      const refreshOnLoad = c.getAttribute('refreshOnLoad') === '1';
      const odcFile = c.getAttribute('odcFile') || '';
      const connectionString = c.getAttribute('connectionString') || '';
      // Some samples push the SQL/command into <dbPr command="..."> or
      // <textPr ...> or <webPr><tables>...</tables></webPr>. Also pull
      // the WebPr URL (xmlns="…/spreadsheetml/2006/main" element <webPr>).
      const dbPr = c.getElementsByTagName('dbPr')[0];
      const dbCommand = dbPr ? (dbPr.getAttribute('command') || '') : '';
      const webPr = c.getElementsByTagName('webPr')[0];
      const webUrl = webPr ? (webPr.getAttribute('url') || '') : '';
      const textPr = c.getElementsByTagName('textPr')[0];
      const textSource = textPr ? (textPr.getAttribute('sourceFile') || '') : '';

      // Aggregate every URL/UNC reference we can find on this connection.
      const candidates = [];
      if (odcFile) candidates.push({ value: odcFile, role: 'odcFile' });
      if (webUrl) candidates.push({ value: webUrl, role: 'webPr/url' });
      if (textSource) candidates.push({ value: textSource, role: 'textPr/sourceFile' });
      // connectionString: strip "Data Source=…" / "Source=…" / "Server=…"
      // — common across OLEDB, ODBC, ADO providers. Also catch unc paths
      // floating bare in the string.
      if (connectionString) {
        const ds = connectionString.match(/(?:Data Source|Source|Server)\s*=\s*([^;]+)/i);
        if (ds && ds[1]) candidates.push({ value: ds[1].trim(), role: 'connectionString/DataSource' });
        // Provider= is informational, not a target — skip.
      }
      // dbCommand frequently carries a downloader command line. Surface as
      // a generic IOC.PATTERN; the actual URL inside is picked up by the
      // shared IOC extractor at runtime, but we still want the cmdline
      // visible as evidence on the workbook itself.
      if (dbCommand && /(?:powershell|cmd\.exe|http|\\\\)/i.test(dbCommand)) {
        out.push({
          type: IOC.PATTERN,
          url: `Connection "${name}" command: ${dbCommand.slice(0, 200)}`,
          severity: 'high',
          note: refreshOnLoad
            ? 'Auto-refresh on open — runs without macro warning'
            : 'Connection dbCommand contains shell-like content',
        });
      }

      for (const { value, role } of candidates) {
        const cls = XlsxConnectionsScanner._classify(value);
        if (!cls) continue; // local relative ref — skip, harmless
        let sev = cls.severity;
        // refreshOnLoad escalates one rank — open-on-execute removes the
        // protective "Enable Content" gate.
        if (refreshOnLoad && sev === 'medium') sev = 'high';
        out.push({
          type: cls.iocType,
          url: value,
          severity: sev,
          note: `xl/connections.xml: connection "${name}" (${role})`
            + (refreshOnLoad ? ' [refreshOnLoad]' : ''),
        });
      }
    }
    return out;
  }

  // Same shape as OoxmlRelScanner._classifyTarget but trimmed: we only need
  // UNC / file / http(s) / ms-protocol classification. Returning null means
  // "not interesting" (local ref, empty, etc.).
  static _classify(t) {
    const v = (t || '').trim();
    if (!v) return null;
    if (/^\\\\(?!\?\\)[^\\]+\\/.test(v) || /^\\\\\?\\UNC\\/i.test(v)) {
      return { iocType: IOC.UNC_PATH, severity: 'high' };
    }
    if (/^https?:\/\//i.test(v)) {
      return { iocType: IOC.URL, severity: 'medium' };
    }
    if (/^ftp:\/\//i.test(v)) {
      return { iocType: IOC.URL, severity: 'high' };
    }
    if (/^file:\/\//i.test(v)) {
      return { iocType: IOC.FILE_PATH, severity: 'medium' };
    }
    if (/^(ms-[a-z]+|ms-word|ms-excel|ms-powerpoint):/i.test(v)) {
      return { iocType: IOC.URL, severity: 'high' };
    }
    return null;
  }
}

class XlsxDataMashupScanner {
  /**
   * Detect Power Query DataMashup payloads in a workbook.
   *
   * Returns at minimum a single banner detection if any DataMashup is
   * present (medium — the mere fact that an xlsx ships executable
   * M-language script is worth surfacing). Additionally extracts and
   * reports any plain-text http(s) / UNC references found inside the
   * DataMashup XML envelope (the inner gzipped payload itself is left
   * to the shared IOC extractor / YARA pipeline — we deliberately do
   * not decompress here, both to keep this helper small and because
   * malformed Power Query payloads are a documented crash vector).
   *
   * @param {JSZip} zip
   * @returns {Promise<Array<{type:string,url:string,severity:string,note:string}>>}
   */
  static async scan(zip) {
    const out = [];
    const items = Object.keys(zip.files).filter(p =>
      /^xl\/customXml\/item\d+\.xml$/i.test(p));
    let banner = false;
    for (const path of items) {
      let text;
      try { text = await zip.file(path).async('string'); }
      catch (e) { continue; }
      // The DataMashup element binds to the "DataMashup" namespace; some
      // tooling emits it as `<DataMashup …>` directly, others wrap it
      // in `<DataMashupSchema>`. Either form contains the literal string
      // "DataMashup".
      if (!/DataMashup/i.test(text)) continue;
      if (!banner) {
        out.push({
          type: IOC.PATTERN,
          url: 'Power Query DataMashup payload present in xl/customXml',
          severity: 'medium',
          note: 'M-language script can call Web.Contents / File.Contents and runs '
            + 'on workbook refresh (auto-refresh-on-open bypasses macro warning)',
        });
        banner = true;
      }
      // Surface any envelope-level plain-text URLs / UNC paths. The base64
      // payload itself is opaque here; the shared IOC scanner picks up
      // strings inside any decoded text we already have.
      const urls = (text.match(/https?:\/\/[^\s"'<>]+/gi) || []).slice(0, 16);
      for (const u of urls) {
        out.push({
          type: IOC.URL,
          url: u,
          severity: 'medium',
          note: `DataMashup envelope (${path})`,
        });
      }
      const uncs = (text.match(/\\\\[^\s"'<>\\]+\\[^\s"'<>]+/g) || []).slice(0, 8);
      for (const u of uncs) {
        out.push({
          type: IOC.UNC_PATH,
          url: u,
          severity: 'high',
          note: `DataMashup envelope (${path})`,
        });
      }
    }
    return out;
  }
}
