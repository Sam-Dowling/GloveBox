// ════════════════════════════════════════════════════════════════════════════
// archives.spec.ts — Fixture-driven smoke for the archive renderer family
// (`zip`, `sevenz`, `cab`, `iso`, `rar`, gzip, tar — all dispatched via
// the renderer-registry magic / extension passes).
//
// Loupe's archive viewers don't decompress (except gzip/zlib in-line);
// they enumerate the central directory and surface entry paths as
// `IOC.FILE_PATH`. Encrypted archives surface the encryption fact as
// `IOC.PATTERN`. The aggregate-budget guard surfaces an `IOC.INFO` row
// when a recursive archive trips the per-load cap.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  isRiskAtLeast,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

test.describe('archives renderer family', () => {
  const ctx = useSharedBundlePage();

  test('plain ZIP enumerates entries', async () => {
    const findings = await loadFixture(ctx.page, 'examples/archives/example.zip');
    // The ZIP central directory peeks should surface either a
    // `Pattern` row (suspicious-content auto-flag) or a `File Path`
    // row (entry name listing). We accept either to stay robust
    // against renderer-side reorgs.
    expect(
      findings.iocTypes.includes('Pattern')
      || findings.iocTypes.includes('File Path'),
    ).toBe(true);
    expect(findings.yaraInProgress).toBe(false);
  });

  test('encrypted ZIP surfaces an encryption Pattern row', async () => {
    const findings = await loadFixture(ctx.page, 'examples/archives/encrypted-example.zip');
    expect(findings.iocTypes).toContain('Pattern');
    // Encryption is an actionable concern — risk floor should escalate
    // above the default 'low'.
    expect(isRiskAtLeast(findings.risk, 'medium')).toBe(true);
  });

  test('AES-encrypted ZIP also escalates', async () => {
    const findings = await loadFixture(ctx.page, 'examples/archives/aes-encrypted-example.zip');
    expect(findings.iocTypes).toContain('Pattern');
    expect(isRiskAtLeast(findings.risk, 'medium')).toBe(true);
  });

  test('7z archive parses without error', async () => {
    const findings = await loadFixture(ctx.page, 'examples/archives/example.7z');
    // `Sevenz` renderer enumerates the listing-only 7z central
    // directory and pushes entry paths as IOC.FILE_PATH.
    expect(findings.iocTypes).toContain('File Path');
    expect(findings.yaraInProgress).toBe(false);
  });

  test('CAB archive parses without error', async () => {
    const findings = await loadFixture(ctx.page, 'examples/archives/example.cab');
    expect(findings.iocCount + findings.externalRefCount).toBeGreaterThan(0);
    expect(findings.yaraInProgress).toBe(false);
  });

  test('RAR archive parses without error', async () => {
    const findings = await loadFixture(ctx.page, 'examples/archives/example.rar');
    // Listing-only RAR — entry names land as IOC.FILE_PATH.
    expect(findings.iocTypes).toContain('File Path');
    expect(findings.yaraInProgress).toBe(false);
  });

  test('ISO 9660 image enumerates entries', async () => {
    const findings = await loadFixture(ctx.page, 'examples/archives/example.iso');
    expect(findings.iocTypes).toContain('File Path');
    expect(findings.yaraInProgress).toBe(false);
  });

  test('plain TAR archive enumerates entries', async () => {
    const findings = await loadFixture(ctx.page, 'examples/archives/example.tar');
    expect(findings.iocTypes).toContain('File Path');
  });

  test('gzipped tar (.tar.gz) decompresses and enumerates inner TAR', async () => {
    const findings = await loadFixture(ctx.page, 'examples/archives/example.tar.gz');
    expect(findings.iocTypes).toContain('File Path');
  });

  test('recursive ZIP trips the aggregate budget guard', async () => {
    // `recursive-example.zip` is a hand-crafted recursive archive
    // designed to exercise the aggregate-decompressed-bytes cap. The
    // renderer must surface either an IOC.INFO budget banner or a
    // YARA Pattern; never crash. We don't pin the exact warning
    // string — it lives in `archive-budget.js` and is allowed to
    // change wording.
    const findings = await loadFixture(ctx.page, 'examples/archives/recursive-example.zip');
    // Either the budget guard fired (Info / Pattern) or YARA caught
    // the recursive shape — both are acceptable signals.
    const expectAny = findings.iocTypes.some(
      t => ['Info', 'Pattern', 'YARA Match'].includes(t));
    expect(expectAny).toBe(true);
    expect(findings.yaraInProgress).toBe(false);
  });

  test('sha1-hulud worm fixture surfaces high risk', async () => {
    // The `sha1-hulud.zip` fixture mirrors the npm worm shape used in
    // production red-team exercises. Risk floor must escalate.
    const findings = await loadFixture(ctx.page, 'examples/archives/sha1-hulud.zip');
    expect(isRiskAtLeast(findings.risk, 'high')).toBe(true);
    expect(findings.iocTypes).toContain('File Path');
  });
});
