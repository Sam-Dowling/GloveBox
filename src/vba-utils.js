'use strict';
// ════════════════════════════════════════════════════════════════════════════
// vba-utils.js — Shared VBA binary decoding and pattern matching
// Used by: DocxParser, XlsxRenderer, PptxRenderer, SecurityAnalyzer
// ════════════════════════════════════════════════════════════════════════════

/**
 * Decode raw VBA binary (Uint8Array) into an array of module objects.
 * Each item is { name: string, source: string }.
 * Source may be empty when the binary cannot be decoded as printable text.
 *
 * @param {Uint8Array} data  Raw bytes of the vbaProject.bin stream.
 * @returns {{ name: string, source: string }[]}
 */
function parseVBAText(data) {
  const txt = new TextDecoder('latin1').decode(data);
  const mods = [];
  const nameRe = /Attribute VB_Name = "([^"]+)"/g;
  let m;
  while ((m = nameRe.exec(txt)) !== null) mods.push({ name: m[1], source: '' });

  // Extract runs of printable ASCII that look like VBA source lines
  const chunks = (txt.match(/[ -~\r\n\t]{40,}/g) || [])
    .filter(c => /\b(Sub |Function |End Sub|End Function|Dim |Set |If |Then|For |MsgBox|Shell|CreateObject|WScript|AutoOpen|Workbook_Open|Document_Open|Auto_Open)\b/i.test(c));
  const src = chunks.join('\n').trim();

  if (mods.length === 0 && src) mods.push({ name: '(extracted)', source: src });
  else if (mods.length > 0 && src) mods[0].source = src;
  return mods;
}

/**
 * Scan VBA source text for auto-execute hooks and dangerous API patterns.
 *
 * @param {string} src  Decoded VBA source text.
 * @returns {string[]}  Human-readable names of matched patterns.
 */
function autoExecPatterns(src) {
  const pats = [
    [/\bAutoOpen\b/i,                     'AutoOpen (auto-execute)'],
    [/\bDocument_Open\b/i,                'Document_Open (auto-execute)'],
    [/\bAuto_Open\b/i,                    'Auto_Open (auto-execute)'],
    [/\bWorkbook_Open\b/i,                'Workbook_Open (auto-execute)'],
    [/\bShell\s*\(/i,                     'Shell()'],
    [/WScript\.Shell/i,                   'WScript.Shell'],
    [/CreateObject\s*\(\s*["']WScript/i,  'CreateObject(WScript)'],
    [/CreateObject\s*\(\s*["']Scripting/i,'CreateObject(Scripting)'],
    [/\bPowerShell\b/i,                   'PowerShell'],
    [/cmd\.exe/i,                         'cmd.exe'],
    [/cmd\s+\/c/i,                        'cmd /c'],
    [/URLDownloadToFile/i,                'URLDownloadToFile'],
    [/XMLHTTP/i,                          'XMLHTTP (network)'],
    [/WinHttpRequest/i,                   'WinHttpRequest (network)'],
    [/\bRegWrite\b/i,                     'RegWrite'],
    [/\bRegDelete\b/i,                    'RegDelete'],
    [/\bKill\b/i,                         'Kill (delete files)'],
    [/\bEnviron\b/i,                      'Environ'],
    [/\bGetObject\b/i,                    'GetObject'],
    [/\bCallByName\b/i,                   'CallByName'],
  ];
  return pats.filter(([re]) => re.test(src)).map(([, name]) => name);
}
