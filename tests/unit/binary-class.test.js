'use strict';
// binary-class.test.js — context-aware risk weighting policy.
//
// `BinaryClass.classify(ctx)` produces a `{size, trust, kind, family,
// flags, summary}` record from a renderer's view of a parsed binary.
// `BinaryClass.weightFor(klass, severity, category)` and
// `BinaryClass.shouldSurfaceLowSeverity(klass, category)` are the two
// gates the PE / ELF / Mach-O renderers consult when deciding whether
// to bump `riskScore` for a per-cluster issue (anti-debug imports,
// generic networking, capability tagging).
//
// The contract this file pins down:
//   • Critical / high severity is NEVER demoted by trust or family.
//   • signed-trusted media-sdk / system-utility / compiler-toolchain
//     binaries get LOW noise zeroed (`weight === 0`) and SURFACE blocked.
//   • signed-trusted on other families gets a softer demote.
//   • signed (unknown CA) gets a +1 boost on low only — medium stays full.
//   • self-signed / unsigned never demote anything.
//   • Installer kind demotes networking / dynamic-loading low → 0.
//   • BAD categories (injection / cred-theft / ransomware / hooking /
//     persistence) keep ≥ 0.75 weight regardless of signer.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

function fresh() {
  return loadModules([
    'src/trusted-cas.js',
    'src/binary-class.js',
  ], {
    expose: ['BinaryClass', 'TrustedCAs'],
  });
}

test('classify: returns a frozen record with the documented shape', () => {
  const ctx = fresh();
  const k = ctx.BinaryClass.classify({
    sizeBytes: 24 * 1024 * 1024,
    format: 'pe',
    kind: 'dll',
    trustTier: 'signed-trusted',
    imports: ['VirtualAlloc', 'CreateRemoteThread', 'mfplat.dll'],
    dylibs: ['mfplat.dll', 'd3d11.dll'],
  });
  assert.equal(typeof k.size, 'string');
  assert.equal(k.sizeBytes, 24 * 1024 * 1024);
  assert.equal(k.trust, 'signed-trusted');
  assert.equal(k.kind, 'dll');
  // 24 MB is in the 'large' tier (10 MB ≤ … < 50 MB).
  assert.equal(k.size, 'large');
  // Frozen so the renderer can't accidentally mutate the classifier
  // output before passing it back into weightFor.
  assert.equal(Object.isFrozen(k), true);
  assert.equal(Object.isFrozen(k.flags), true);
});

test('classify: size tier boundaries (tiny / small / medium / large / huge)', () => {
  const ctx = fresh();
  const c = (n) => ctx.BinaryClass.classify({ sizeBytes: n, format: 'pe' }).size;
  assert.equal(c(0), 'tiny');
  assert.equal(c(99 * 1024), 'tiny');
  assert.equal(c(100 * 1024), 'small');
  assert.equal(c(1024 * 1024 - 1), 'small');
  assert.equal(c(1024 * 1024), 'medium');
  assert.equal(c(10 * 1024 * 1024 - 1), 'medium');
  assert.equal(c(10 * 1024 * 1024), 'large');
  assert.equal(c(50 * 1024 * 1024 - 1), 'large');
  assert.equal(c(50 * 1024 * 1024), 'huge');
  assert.equal(c(500 * 1024 * 1024), 'huge');
});

test('weightFor: critical/high severity is NEVER demoted', () => {
  const ctx = fresh();
  // Even the most aggressive demotion case (signed-trusted media-sdk
  // + low-noise category) must keep weight=1 for critical/high.
  const k = ctx.BinaryClass.classify({
    sizeBytes: 24 * 1024 * 1024,
    format: 'pe',
    kind: 'dll',
    trustTier: 'signed-trusted',
    dylibs: ['mfplat.dll', 'd3d11.dll'],
  });
  assert.equal(ctx.BinaryClass.weightFor(k, 'critical', 'anti-debug'), 1);
  assert.equal(ctx.BinaryClass.weightFor(k, 'high', 'networking'), 1);
  assert.equal(ctx.BinaryClass.weightFor(k, 'critical', 'injection'), 1);
});

test('weightFor: signed-trusted media-sdk zeros LOW noise, halves MEDIUM', () => {
  const ctx = fresh();
  const k = ctx.BinaryClass.classify({
    sizeBytes: 24 * 1024 * 1024,
    format: 'pe',
    kind: 'dll',
    trustTier: 'signed-trusted',
    dylibs: ['mfplat.dll', 'd3d11.dll'],
  });
  assert.equal(k.family, 'media-sdk');
  assert.equal(ctx.BinaryClass.weightFor(k, 'low',    'anti-debug'),       0);
  assert.equal(ctx.BinaryClass.weightFor(k, 'low',    'networking'),       0);
  assert.equal(ctx.BinaryClass.weightFor(k, 'low',    'dynamic-loading'),  0);
  assert.equal(ctx.BinaryClass.weightFor(k, 'low',    'timing'),           0);
  assert.equal(ctx.BinaryClass.weightFor(k, 'medium', 'anti-debug'),       0.5);
  assert.equal(ctx.BinaryClass.weightFor(k, 'medium', 'networking'),       0.5);
});

test('weightFor: signed-trusted other families get softer demote', () => {
  const ctx = fresh();
  const k = ctx.BinaryClass.classify({
    sizeBytes: 5 * 1024 * 1024,
    format: 'pe',
    kind: 'exe',
    trustTier: 'signed-trusted',
    // No media / compiler / system-utility hints → family='unknown'.
    imports: ['CreateProcessW', 'WinHttpOpen'],
  });
  assert.equal(k.family, 'unknown');
  assert.equal(ctx.BinaryClass.weightFor(k, 'low',    'networking'), 0.5);
  assert.equal(ctx.BinaryClass.weightFor(k, 'medium', 'networking'), 0.75);
});

test('weightFor: signed (unknown CA) halves LOW only — MEDIUM stays full', () => {
  const ctx = fresh();
  const k = ctx.BinaryClass.classify({
    sizeBytes: 5 * 1024 * 1024,
    format: 'pe',
    kind: 'exe',
    trustTier: 'signed',
    imports: ['Sleep'],
  });
  assert.equal(ctx.BinaryClass.weightFor(k, 'low',    'timing'),     0.5);
  assert.equal(ctx.BinaryClass.weightFor(k, 'low',    'anti-debug'), 0.5);
  assert.equal(ctx.BinaryClass.weightFor(k, 'medium', 'anti-debug'), 1);
});

test('weightFor: unsigned / self-signed never demote', () => {
  const ctx = fresh();
  for (const tier of ['unsigned', 'self-signed']) {
    const k = ctx.BinaryClass.classify({
      sizeBytes: 5 * 1024 * 1024,
      format: 'pe',
      kind: 'exe',
      trustTier: tier,
    });
    assert.equal(ctx.BinaryClass.weightFor(k, 'low',    'anti-debug'), 1, `tier=${tier} low/anti-debug`);
    assert.equal(ctx.BinaryClass.weightFor(k, 'medium', 'networking'), 1, `tier=${tier} medium/networking`);
  }
});

test('weightFor: BAD categories keep ≥ 0.75 weight regardless of signer', () => {
  const ctx = fresh();
  // Even with the most demoting trust+family combo the BAD categories
  // (injection / cred-theft / ransomware / hooking / persistence)
  // contribute essentially full weight. This is the core safety
  // invariant: a stolen / leaked code-sig must NEVER suppress an
  // injection capability.
  const k = ctx.BinaryClass.classify({
    sizeBytes: 24 * 1024 * 1024,
    format: 'pe',
    kind: 'dll',
    trustTier: 'signed-trusted',
    dylibs: ['mfplat.dll'],
  });
  for (const cat of ['injection', 'cred-theft', 'ransomware', 'hooking', 'persistence']) {
    assert.equal(ctx.BinaryClass.weightFor(k, 'medium', cat), 1, `medium/${cat}`);
    assert.equal(ctx.BinaryClass.weightFor(k, 'low',    cat), 0.75, `low/${cat}`);
  }
});

test('weightFor: installer demotes networking/exec/dyn-loading low → 0', () => {
  const ctx = fresh();
  const k = ctx.BinaryClass.classify({
    sizeBytes: 5 * 1024 * 1024,
    format: 'pe',
    kind: 'installer',
    trustTier: 'unsigned',
    installerType: 'NSIS',
  });
  assert.equal(ctx.BinaryClass.weightFor(k, 'low',    'networking'),       0);
  assert.equal(ctx.BinaryClass.weightFor(k, 'low',    'execution'),        0);
  assert.equal(ctx.BinaryClass.weightFor(k, 'low',    'dynamic-loading'),  0);
  assert.equal(ctx.BinaryClass.weightFor(k, 'medium', 'networking'),       0.5);
  // Anti-debug / timing on an installer are still suspicious — installers
  // don't legitimately need to detect a debugger.
  assert.equal(ctx.BinaryClass.weightFor(k, 'low',    'anti-debug'),       1);
});

test('shouldSurfaceLowSeverity: hides anti-debug / timing on signed-trusted system binaries', () => {
  const ctx = fresh();
  const k = ctx.BinaryClass.classify({
    sizeBytes: 24 * 1024 * 1024,
    format: 'pe',
    kind: 'dll',
    trustTier: 'signed-trusted',
    dylibs: ['mfplat.dll'],
  });
  assert.equal(ctx.BinaryClass.shouldSurfaceLowSeverity(k, 'anti-debug'),       false);
  assert.equal(ctx.BinaryClass.shouldSurfaceLowSeverity(k, 'timing'),           false);
  assert.equal(ctx.BinaryClass.shouldSurfaceLowSeverity(k, 'dynamic-loading'),  false);
  // Cred-theft and injection MUST still surface.
  assert.equal(ctx.BinaryClass.shouldSurfaceLowSeverity(k, 'cred-theft'),       true);
  assert.equal(ctx.BinaryClass.shouldSurfaceLowSeverity(k, 'injection'),        true);
});

test('shouldSurfaceLowSeverity: returns true on null klass (no classifier output)', () => {
  // The classifier can return null in `analyzeForSecurity` if BinaryClass
  // wasn't loaded yet (defensive). The renderer's `_surface` helper still
  // calls through here with the null record.
  const ctx = fresh();
  assert.equal(ctx.BinaryClass.shouldSurfaceLowSeverity(null, 'anti-debug'), true);
  assert.equal(ctx.BinaryClass.weightFor(null, 'low', 'anti-debug'), 1);
});

test('classify: `large` boolean is true at the large/huge size tiers', () => {
  // PE renderer's reflective-DLL gate keys off `binaryClass.large` to
  // demote the ubiquitous-API quorum on big SDKs (where coincidental
  // VirtualAlloc + VirtualProtect + CreateThread is the norm).
  const ctx = fresh();
  const c = (n) => ctx.BinaryClass.classify({ sizeBytes: n, format: 'pe' });
  assert.equal(c(1024).large, false, 'tiny');
  assert.equal(c(500 * 1024).large, false, 'small');
  assert.equal(c(5 * 1024 * 1024).large, false, 'medium');
  assert.equal(c(10 * 1024 * 1024).large, true, 'large lower bound');
  assert.equal(c(33 * 1024 * 1024).large, true, 'large mid');
  assert.equal(c(100 * 1024 * 1024).large, true, 'huge');
});
