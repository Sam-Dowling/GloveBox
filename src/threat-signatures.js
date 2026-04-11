'use strict';
// ════════════════════════════════════════════════════════════════════════════
// threat-signatures.js — Centralised threat signature database + scanner
// Depends on: constants.js
// ════════════════════════════════════════════════════════════════════════════

/**
 * Signature categories and their entries.
 * Each entry: { string, score }
 *   score 3 = high-severity (execution, download, injection)
 *   score 2 = medium-severity (obfuscation, suspicious API)
 *   score 1 = informational in isolation
 */
const ThreatSignatures = {

  pdf: [
    { string: '/OpenAction',          score: 3 },
    { string: '/AA',                  score: 3 },
    { string: '/JavaScript',          score: 3 },
    { string: '/JS',                  score: 3 },
    { string: '/AcroForm',            score: 2 },
    { string: '/XFA',                 score: 3 },
    { string: '/URI',                 score: 2 },
    { string: '/SubmitForm',          score: 2 },
    { string: '/GoToR',               score: 2 },
    { string: '/RichMedia',           score: 3 },
    { string: '/ObjStm',              score: 2 },
    { string: '/XObject',             score: 1 },
    { string: 'eval',                 score: 3 },
    { string: 'String.fromCharCode',  score: 3 },
    { string: 'unescape',             score: 3 },
    { string: 'atob',                 score: 2 },
    { string: 'launch',               score: 3 },
    { string: 'EmbeddedFile',         score: 2 },
  ],

  office_vba: [
    { string: 'AutoOpen',                score: 3 },
    { string: 'Auto_Open',               score: 3 },
    { string: 'Document_Open',           score: 3 },
    { string: 'Workbook_Open',           score: 3 },
    { string: 'Document_Close',          score: 3 },
    { string: 'Shell',                   score: 3 },
    { string: 'WScript.Shell',           score: 3 },
    { string: 'Run',                     score: 3 },
    { string: 'Exec',                    score: 3 },
    { string: 'ShellExecute',            score: 3 },
    { string: 'CreateObject',            score: 3 },
    { string: 'GetObject',               score: 3 },
    { string: 'Shell.Application',       score: 3 },
    { string: 'URLDownloadToFileA',      score: 3 },
    { string: 'Microsoft.XMLHTTP',       score: 3 },
    { string: 'WinHttp.WinHttpRequest',  score: 3 },
    { string: 'ADODB.Stream',            score: 3 },
    { string: 'Chr',                     score: 2 },
    { string: 'ChrW',                    score: 2 },
    { string: 'wbemdisp.dll',            score: 2 },
    { string: 'DDEAUTO',                 score: 3 },
    { string: 'DDE',                     score: 3 },
    { string: 'powershell',              score: 3 },
    { string: 'New-Object',              score: 3 },
  ],

  javascript: [
    { string: 'eval',                 score: 3 },
    { string: 'String.fromCharCode',  score: 3 },
    { string: 'unescape',             score: 3 },
    { string: 'atob',                 score: 2 },
    { string: 'decodeURIComponent',   score: 2 },
    { string: 'document.write',       score: 3 },
    { string: 'ActiveXObject',        score: 3 },
    { string: 'WScript.Shell',        score: 3 },
    { string: 'XMLHttpRequest',       score: 3 },
    { string: 'MSXML2.XMLHTTP',       score: 3 },
    { string: 'window.location',      score: 2 },
  ],

  powershell: [
    { string: '-EncodedCommand',              score: 3 },
    { string: '-e',                           score: 3 },
    { string: '-enc',                         score: 3 },
    { string: '-nop',                         score: 3 },
    { string: '-noni',                        score: 3 },
    { string: '-w hidden',                    score: 3 },
    { string: 'Invoke-Expression',            score: 3 },
    { string: 'iex',                          score: 3 },
    { string: 'Invoke-Command',               score: 3 },
    { string: 'DownloadString',               score: 3 },
    { string: 'DownloadFile',                 score: 3 },
    { string: 'Invoke-WebRequest',            score: 3 },
    { string: 'Start-BitsTransfer',           score: 3 },
    { string: 'System.Reflection.Assembly',   score: 3 },
    { string: 'Add-Type',                     score: 3 },
  ],

  pe_binaries: [
    { string: 'VirtualAlloc',           score: 3 },
    { string: 'WriteProcessMemory',     score: 3 },
    { string: 'CreateRemoteThread',     score: 3 },
    { string: 'InternetConnectA',       score: 3 },
    { string: 'URLDownloadToFile',      score: 3 },
    { string: 'WinExec',                score: 3 },
    { string: 'CreateProcessA',         score: 3 },
    { string: 'VirtualProtect',         score: 3 },
    { string: 'RtlMoveMemory',          score: 3 },
    { string: 'LoadLibraryA',           score: 2 },
  ],

  general_obfuscation: [
    { string: 'base64',           score: 2 },
    { string: 'fromCharCode',     score: 3 },
    { string: 'Chr(',             score: 2 },
    { string: 'hex-encoded',      score: 2 },
    { string: 'xor',              score: 2 },
    { string: 'IEX $env:',        score: 3 },
  ],
};

// ── ThreatScanner ──────────────────────────────────────────────────────────

class ThreatScanner {

  /**
   * Map score values to severity strings.
   */
  static scoreSeverity(score) {
    if (score >= 3) return 'high';
    if (score >= 2) return 'medium';
    return 'info';
  }

  /**
   * Determine which signature categories apply to a given file.
   * @param {string} fileName
   * @param {string} [fileType]  Optional override: 'pdf', 'office', 'script', etc.
   * @returns {string[]}  Category names from ThreatSignatures
   */
  static getCategories(fileName, fileType) {
    const ext = (fileName || '').split('.').pop().toLowerCase();
    const cats = ['general_obfuscation'];

    if (fileType === 'pdf' || ext === 'pdf') {
      cats.push('pdf', 'javascript');
    } else if (fileType === 'office' || ['docx','docm','xlsx','xlsm','xls','pptx','pptm','doc','ods'].includes(ext)) {
      cats.push('office_vba');
    } else if (['js','jse','wsf','wsh','htm','html','hta','mht','mhtml','xhtml','svg'].includes(ext)) {
      cats.push('javascript');
    } else if (['ps1','psm1','psd1'].includes(ext)) {
      cats.push('powershell');
    } else if (['vbs','vbe'].includes(ext)) {
      cats.push('office_vba', 'javascript');
    } else if (['exe','dll','sys','scr','ocx','cpl','drv'].includes(ext)) {
      cats.push('pe_binaries');
    } else if (['bat','cmd'].includes(ext)) {
      cats.push('powershell', 'office_vba');
    } else {
      // For unknown types, scan broadly
      cats.push('javascript', 'powershell', 'office_vba');
    }
    return cats;
  }

  /**
   * Scan a text string against the specified signature categories.
   * @param {string} text         Content to scan
   * @param {string[]} categories Category names from ThreatSignatures
   * @returns {{ category: string, string: string, score: number, severity: string, count: number }[]}
   */
  static scan(text, categories) {
    if (!text) return [];
    const results = [];
    const seen = new Set();

    for (const cat of categories) {
      const sigs = ThreatSignatures[cat];
      if (!sigs) continue;
      for (const sig of sigs) {
        const key = cat + '|' + sig.string;
        if (seen.has(key)) continue;
        seen.add(key);
        const count = ThreatScanner._countOccurrences(text, sig.string);
        if (count > 0) {
          results.push({
            category: cat,
            string: sig.string,
            score: sig.score,
            severity: ThreatScanner.scoreSeverity(sig.score),
            count
          });
        }
      }
    }
    return results;
  }

  /**
   * Scan raw binary buffer by decoding as latin-1 then running signature scan.
   * @param {ArrayBuffer|Uint8Array} buffer
   * @param {string[]} categories
   * @returns {Array}  Same format as scan()
   */
  static scanBuffer(buffer, categories) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const chunks = [];
    const CHUNK = 512 * 1024;
    for (let i = 0; i < bytes.length; i += CHUNK) {
      chunks.push(String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK)));
    }
    return ThreatScanner.scan(chunks.join(''), categories);
  }

  /**
   * Compute aggregate threat level from signature matches.
   * @param {{ score: number }[]} matches
   * @returns {{ level: string, totalScore: number, maxScore: number }}
   */
  static computeThreatLevel(matches) {
    if (!matches || !matches.length) return { level: 'low', totalScore: 0, maxScore: 0 };
    let total = 0, max = 0;
    for (const m of matches) {
      total += m.score * m.count;
      if (m.score > max) max = m.score;
    }
    let level = 'low';
    if (max >= 3 || total >= 10) level = 'high';
    else if (max >= 2 || total >= 5) level = 'medium';
    return { level, totalScore: total, maxScore: max };
  }

  /**
   * Convert signature matches into findings-compatible externalRefs entries.
   * @param {Array} matches  Output of scan()/scanBuffer()
   * @returns {Array}  Array of { type, url, severity } for sidebar display
   */
  static toFindings(matches) {
    return matches.map(m => ({
      type: `Signature [${m.category}]`,
      url: `${m.string} — ${m.count} occurrence(s) [score: ${m.score}]`,
      severity: m.severity
    }));
  }

  // ── Internal helpers ─────────────────────────────────────────────────────

  /**
   * Count case-insensitive occurrences of needle in haystack.
   */
  static _countOccurrences(haystack, needle) {
    // Escape regex special chars in the needle for literal matching
    const escaped = needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const rx = new RegExp(escaped, 'gi');
    const m = haystack.match(rx);
    return m ? m.length : 0;
  }
}
