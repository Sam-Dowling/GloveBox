// binary-class.js — Cheap binary classifier for context-aware risk weighting.
//
// Calibrates "is this finding plausibly suspicious *for this kind of
// binary*?". A 50 KB unsigned binary calling `VirtualAlloc` +
// `CreateRemoteThread` is suspicious; a 24 MB signed media-SDK DLL calling
// the same APIs is doing memory management. Without this calibration every
// ubiquitous Win32 API generates a noise finding.
//
// Pure function; no DOM, no localStorage, no network.
//
// Contract
// --------
//   BinaryClass.classify(ctx) → {
//     size:        'tiny' | 'small' | 'medium' | 'large' | 'huge',
//     sizeBytes:   number,
//     large:       boolean — true when size tier is 'large' or 'huge'
//                  (≥ 10 MB). Convenience flag used by renderers to demote
//                  ubiquitous-API quorums whose false-positive rate
//                  scales with binary size (e.g. reflective-DLL trio).
//     trust:       'unsigned' | 'self-signed' | 'signed' | 'signed-trusted',
//     trustBoost:  -1 | 0 | 1 | 2,
//     kind:        'driver' | 'dll' | 'exe' | 'service' | 'installer' | 'library',
//     family:      'media-sdk' | 'security-tool' | 'compiler-toolchain'
//                | 'system-utility' | 'gui-app' | 'cli-tool' | 'unknown',
//     flags:       { isDotNet, isGoBinary, isXll, isAutoHotkey, isInstaller,
//                    isDriver, hasManyImports, hasResources, hasDebugInfo },
//     summary:     human-readable one-liner (for Summary metadata row)
//   }
//
// Inputs (all optional — classifier is forgiving):
//   ctx.sizeBytes      number             — file size
//   ctx.format         'pe'|'elf'|'macho'
//   ctx.kind           pre-classified kind hint, optional
//   ctx.trustTier      string             — output of TrustedCAs.classifyTrustTier
//   ctx.metadata       object             — `findings.metadata`
//   ctx.imports        Array<string>      — lowercased import names
//   ctx.dylibs         Array<string>      — lowercased dylib/dll basenames
//   ctx.flags          object             — { isDotNet, isGoBinary, isXll, ... }
//   ctx.installerType  string|null        — `pe.installerType`
//   ctx.subsystem      string|null        — Windows subsystem string
//
// `trustBoost` mapping is delegated to `TrustedCAs.trustBoostForTier`
// (loaded from `trusted-cas.js` ahead of this file).

const _SIZE_TIERS = [
  // [upper-bound exclusive, label]
  [   100 * 1024,  'tiny'   ],   // < 100 KB
  [  1024 * 1024,  'small'  ],   // < 1 MB
  [ 10 * 1024 * 1024, 'medium' ],// < 10 MB
  [ 50 * 1024 * 1024, 'large'  ],// < 50 MB
  [ Infinity,      'huge'   ],   // ≥ 50 MB
];

function _sizeTier(n) {
  const v = Number(n) || 0;
  for (const [bound, label] of _SIZE_TIERS) {
    if (v < bound) return label;
  }
  return 'huge';
}

// Family detection — driven by hints already on `findings.metadata` and
// the imported DLL / dylib basenames. Order matters: more specific families
// are checked first so a "media-sdk DLL" doesn't get re-classified as
// "system-utility".

const _FAMILY_DLL_HINTS = Object.freeze({
  'media-sdk': [
    'mfplat.dll', 'mfreadwrite.dll', 'mf.dll', 'mfcore.dll', 'mfsensorgroup.dll',
    'd3d11.dll', 'd3d12.dll', 'd3d9.dll', 'dxgi.dll', 'dxva2.dll',
    'avcodec', 'avformat', 'avutil', 'libav', 'ffmpeg',
    'gdiplus.dll', 'wmvcore.dll', 'amdxc64.dll', 'nvcuda.dll',
    'opengl32.dll', 'libavcodec', 'libavformat',
    'mediafoundation', 'webrtc', 'libvpx',
    // macOS / Linux equivalents
    'avfoundation', 'coremedia', 'coreaudio', 'audiotoolbox',
    'libgstreamer', 'libpulse', 'libasound', 'libpipewire',
  ],
  'security-tool': [
    'wintrust.dll', 'cryptui.dll', 'msasn1.dll',
    // EDR / AV product DLLs that sometimes get statically linked.
    'libssl', 'libcrypto', 'libcurl',
  ],
  'compiler-toolchain': [
    'msvcr', 'msvcp', 'vcruntime', 'ucrtbase.dll',
    'libstdc++', 'libgcc', 'libc++', 'libobjc',
  ],
});

const _FAMILY_NAME_HINTS = Object.freeze({
  'media-sdk': [
    'codec', 'media', 'video', 'audio', 'streaming', 'webrtc',
    'camera', 'capture', 'directx', 'direct3d', 'opengl', 'vulkan',
    'ffmpeg', 'gstreamer', 'rendering', 'render engine',
    'player', 'broadcast', 'imaging',
  ],
  'security-tool': [
    'antivirus', 'endpoint', 'edr', 'malware', 'threat', 'sandbox',
    'forensic', 'reverse', 'debugger', 'analyzer', 'scanner',
    'vulnerability', 'firewall',
  ],
  'compiler-toolchain': [
    'compiler', 'linker', 'sdk', 'runtime', 'toolchain', 'devkit',
    'visual studio', 'msbuild', 'mingw', 'llvm', 'clang', 'gcc',
  ],
  'system-utility': [
    'driver', 'service', 'utility', 'manager', 'updater', 'installer',
    'system tools', 'control panel', 'platform', 'agent',
  ],
});

function _hasAny(haystack, needles) {
  if (!haystack) return false;
  for (const n of needles) {
    if (haystack.indexOf(n) >= 0) return true;
  }
  return false;
}

function _detectFamily(ctx) {
  const md = ctx.metadata || {};
  const dylibs = (Array.isArray(ctx.dylibs) ? ctx.dylibs : [])
    .map(s => String(s || '').toLowerCase());
  const dylibJoined = dylibs.join(' ');

  // Concatenate descriptive metadata fields for keyword matching.
  const blob = [
    md['Product Name'], md['File Description'], md['Original Filename'],
    md['Internal Name'], md['Company Name'], md['Format'],
    md['Installer'], md['Go Module Path'],
  ].filter(Boolean).join(' · ').toLowerCase();

  // 1. DLL-set hints (strongest signal).
  for (const [family, hints] of Object.entries(_FAMILY_DLL_HINTS)) {
    if (_hasAny(dylibJoined, hints)) return family;
  }
  // 2. Descriptive metadata keyword hints.
  for (const [family, hints] of Object.entries(_FAMILY_NAME_HINTS)) {
    if (_hasAny(blob, hints)) return family;
  }
  // 3. Subsystem hints (PE only).
  const subsys = String(ctx.subsystem || '').toLowerCase();
  if (subsys.indexOf('console') >= 0) return 'cli-tool';
  if (subsys.indexOf('windows gui') >= 0 || subsys.indexOf('windows_gui') >= 0) return 'gui-app';
  if (subsys.indexOf('native') >= 0 || subsys.indexOf('driver') >= 0) return 'system-utility';

  return 'unknown';
}

function _detectKind(ctx) {
  if (ctx.kind) return ctx.kind;
  const md = ctx.metadata || {};
  const t = String(md['Type'] || '').toLowerCase();
  if (t.indexOf('driver') >= 0)  return 'driver';
  if (t.indexOf('dll')    >= 0)  return 'dll';
  if (ctx.installerType)         return 'installer';
  if (md['Installer'])           return 'installer';
  if (t.indexOf('executable') >= 0) return 'exe';
  // ELF / Mach-O fallback: `Format` may say 'shared object' / 'dylib'.
  const f = String(md['Format'] || '').toLowerCase();
  if (f.indexOf('shared') >= 0 || f.indexOf('dylib') >= 0 || f.indexOf('library') >= 0) {
    return 'library';
  }
  return 'exe';
}

/**
 * Classify a parsed binary into a small label-bag used by the riskScore
 * gating helpers. See file header for the contract.
 */
function classifyBinary(ctx) {
  ctx = ctx || {};
  const sizeBytes = Number(ctx.sizeBytes) || 0;
  const size      = _sizeTier(sizeBytes);
  const trust     = ctx.trustTier || 'unsigned';
  const trustBoost = (typeof TrustedCAs !== 'undefined' && TrustedCAs.trustBoostForTier)
    ? TrustedCAs.trustBoostForTier(trust)
    : 0;
  const kind      = _detectKind(ctx);
  const family    = _detectFamily(ctx);

  const flags = Object.assign({
    isDotNet:       false,
    isGoBinary:     false,
    isXll:          false,
    isAutoHotkey:   false,
    isInstaller:    kind === 'installer',
    isDriver:       kind === 'driver',
    hasManyImports: Array.isArray(ctx.imports) && ctx.imports.length > 100,
    hasResources:   false,
    hasDebugInfo:   false,
  }, ctx.flags || {});

  // Derive a one-line human summary for Summary / sidebar metadata row.
  const sizeStr = sizeBytes >= 1024 * 1024
    ? (sizeBytes / (1024 * 1024)).toFixed(1) + ' MB'
    : sizeBytes >= 1024
      ? (sizeBytes / 1024).toFixed(0) + ' KB'
      : sizeBytes + ' B';
  const familyStr = family === 'unknown' ? '' : ' · ' + family;
  const summary = `${size} (${sizeStr}) · ${trust}${familyStr}`;

  // Convenience boolean: "is this a large binary?". `large` is true when
  // the size tier is `'large'` (≥ 10 MB, < 50 MB) or `'huge'` (≥ 50 MB).
  // Capability gates that suffer from coincidental ubiquitous-API quorum
  // matches (e.g. proc-injection-reflective on signed media SDKs) use
  // this to suppress / demote on big binaries where the false-positive
  // rate is highest.
  const large = (size === 'large' || size === 'huge');

  return Object.freeze({
    size,
    sizeBytes,
    large,
    trust,
    trustBoost,
    kind,
    family,
    flags: Object.freeze(flags),
    summary,
  });
}

/**
 * Compute a multiplier ∈ [0..1] to apply to a per-capability riskScore
 * contribution. Lets renderers gate ubiquitous-API noise by the binary's
 * trust / family / kind triple without re-implementing the policy in
 * three different `analyzeForSecurity` functions.
 *
 *   severity     'critical'  always 1.0  (never demoted)
 *   severity     'high'      always 1.0  (never demoted)
 *   severity     'medium'    demoted by trust+family
 *   severity     'low'/'info' demoted aggressively
 *
 * Concrete cases:
 *   • signed-trusted media-sdk → 0   for low / 0.5 for medium
 *   • signed-trusted any       → 0.5 for low / 0.75 for medium
 *   • signed (unknown CA)      → 0.5 for low / 1.0 for medium
 *   • self-signed / unsigned   → 1.0 across the board
 *   • installer (kind)         → networking / dynamic-loading low → 0
 *
 * Renderers pass the actual cluster severity (`'low'`/`'medium'`/`'high'`/
 * `'critical'`) and a cluster category string (`'anti-debug'`,
 * `'networking'`, `'dynamic-loading'`, `'timing'`, `'injection'`,
 * `'cred-theft'`, `'crypto'`, `'persistence'`, `'execution'`).
 */
function weightFor(klass, severity, category) {
  if (!klass) return 1;
  if (severity === 'critical' || severity === 'high') return 1;

  const trust = klass.trust;
  const family = klass.family;
  const kind = klass.kind;

  // Categories that stay near full weight regardless of signer.
  const BAD = new Set(['injection', 'cred-theft', 'ransomware', 'hooking', 'persistence']);

  if (BAD.has(category)) return severity === 'medium' ? 1 : 0.75;

  if (trust === 'signed-trusted') {
    if (family === 'media-sdk' || family === 'compiler-toolchain' || family === 'system-utility') {
      return severity === 'medium' ? 0.5 : 0;
    }
    return severity === 'medium' ? 0.75 : 0.5;
  }
  if (trust === 'signed') {
    return severity === 'medium' ? 1 : 0.5;
  }

  // Installers expect to launch processes and download payloads.
  if (kind === 'installer' && (category === 'networking' || category === 'execution' || category === 'dynamic-loading')) {
    return severity === 'medium' ? 0.5 : 0;
  }

  // Drivers / .NET / etc. unsigned → full weight.
  return 1;
}

/**
 * Convenience: should a low-severity cluster issue even be SURFACED
 * (pushed as a PATTERN IOC + autoExec issue) given the class? Returning
 * false makes the renderer suppress the row entirely; it still records the
 * fact in `findings.metadata` so the analyst can audit if needed.
 */
function shouldSurfaceLowSeverity(klass, category) {
  if (!klass) return true;
  if (klass.trust === 'signed-trusted'
      && (klass.family === 'media-sdk' || klass.family === 'compiler-toolchain' || klass.family === 'system-utility')
      && (category === 'anti-debug' || category === 'timing' || category === 'dynamic-loading')) {
    return false;
  }
  if (klass.kind === 'installer' && (category === 'networking' || category === 'dynamic-loading')) {
    return false;
  }
  return true;
}

const BinaryClass = Object.freeze({
  classify: classifyBinary,
  weightFor,
  shouldSurfaceLowSeverity,
});
