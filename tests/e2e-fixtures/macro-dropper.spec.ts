// ════════════════════════════════════════════════════════════════════════════
// macro-dropper.spec.ts — End-to-end coverage for the
// Office VBA macro-dropper rule cluster (`src/rules/office-macros.yar`).
//
// `examples/office/macro-dropper.docm` is a synthetic OOXML built by
// `scripts/misc/generate_macro_dropper_docm.py`. It is NOT a runnable
// Word macro — Word would silently discard the auxiliary
// `word/vbaModuleSource.bas` part on open because the package has no
// real OLE-CFB `vbaProject.bin`. The fixture exists for one reason:
// pin every VBA_* threat rule's literal-substring match in a single
// deterministic file.
//
// What this spec proves:
//   1. Loupe routes the file through the docm pipeline (formatTag
//      'docx') — the renderer-registry entry for 'docx' includes
//      the 'docm' extension, and `_rendererDispatch.docx` is the
//      canonical handler.
//   2. The full 16-rule VBA_* cluster fires (every threat rule in
//      `office-macros.yar` whose magic gate matches a ZIP, EXCEPT
//      the two ActiveX/DDE-shape rules that need different
//      structural markers). Before this fixture every VBA_* rule
//      below `Office_Macro_Project_Present` was unanchored —
//      `tests/e2e-fixtures/yara-rules-fired.json` listed all 16 in
//      `unanchoredRules`. Listing them explicitly here gives a
//      single-rule-resolution regression signal rather than a
//      family-aggregate.
//   3. The 3-rule office-relationship cluster fires
//      (`Office_Remote_Template_Injection`,
//      `Office_External_Relationship`, `OOXML_External_Template`)
//      from the `attachedTemplate` + `Target="https://..."` pair
//      planted in `word/_rels/document.xml.rels`.
//   4. Risk floor escalates to 'critical' (5+ critical-severity
//      rules ⇒ `escalateRisk(findings, 'critical')`).
//
// Why one spec instead of relying on `snapshot-matrix.spec.ts`:
//   The matrix pins at most three "family-anchor" rules per fixture
//   (intentional — see `scripts/gen_expected.py` header). This spec
//   pins the FULL 19-rule cluster so the office-macros rule pack as a
//   system has visible regression coverage, not just the first three
//   sorted alphabetically.
//
// Why this works structurally — see the generator header for the full
// rationale, but the short version: every rule in `office-macros.yar`
// gates on `(uint32(0)==0xE011CFD0 or uint16(0)==0x4B50 or
// uint32(0)==0x74725C7B)` and matches LITERAL substrings anywhere in
// the file. The .docm starts with `PK\x03\x04` so the magic gate
// passes; the auxiliary VBA part is stored UNCOMPRESSED so the
// keyword strings appear contiguously in the .docm bytes. Loupe's
// docm route passes the raw file ArrayBuffer to YARA (no `_rawText`
// remap because content-renderer.js doesn't set one), so the rules
// see the literals.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  dumpResult,
  ruleNames,
  isRiskAtLeast,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

// The full VBA_* rule set this fixture is designed to anchor.
// Order matches the rule definitions in `src/rules/office-macros.yar`
// for ease of cross-reference.
const TARGETED_VBA_RULES = [
  'VBA_AutoExec_Trigger',
  'VBA_Shell_Execution',
  'VBA_Download_Capability',
  'VBA_Obfuscation_Techniques',
  'VBA_PowerShell_Invocation',
  'VBA_Environment_Enumeration',
  'VBA_File_System_Write',
  'VBA_Registry_Manipulation',
  'VBA_Scheduled_Task_Persistence',
  'VBA_MSHTA_Invocation',
  'VBA_Certutil_Decode',
  'VBA_Sleep_Delay',
  'VBA_GetObject_WMI',
  'VBA_Shell_Application_Abuse',
  'VBA_NewObject_PowerShell',
  'VBA_WbemDisp_WMI',
];

// Office-relationship rules anchored by the planted
// `attachedTemplate` + `Target="https://..."` in `word/_rels/`.
const TARGETED_OFFICE_RULES = [
  'Office_Remote_Template_Injection',
  'Office_External_Relationship',
  'OOXML_External_Template',
];

test.describe('Office macro-dropper (office-macros.yar cluster)', () => {
  const ctx = useSharedBundlePage();

  test('macro-dropper.docm anchors the full VBA + Office threat cluster', async () => {
    const findings = await loadFixture(
      ctx.page, 'examples/office/macro-dropper.docm');
    const result = await dumpResult(ctx.page);

    // ── 1. Format pin ─────────────────────────────────────────────────
    // The renderer-registry entry for 'docx' includes the 'docm'
    // extension; both flow through `_rendererDispatch.docx` which
    // builds the parsed-doc DOM tree (no `_rawText` set, so YARA
    // scans the raw zip bytes — that's the property the rule pack
    // relies on).
    expect(result?.timeline ?? false).toBe(false);
    expect(result?.formatTag).toBe('docx');

    // ── 2. VBA_* rule cluster ─────────────────────────────────────────
    // Every targeted rule must fire. `expect.soft` so a single
    // missing rule surfaces every other gap in the same run rather
    // than masking N-1 failures behind the first.
    const seen = ruleNames(findings);
    const missingVba = TARGETED_VBA_RULES.filter(r => !seen.includes(r));
    expect.soft(
      missingVba,
      `VBA_* rules expected to fire but didn't: ${missingVba.join(', ')}`,
    ).toEqual([]);

    // ── 3. Office_* relationship cluster ─────────────────────────────
    // Driven by the `attachedTemplate` + Target="https://..." pair
    // in `word/_rels/document.xml.rels` (generator plants both).
    const missingOffice = TARGETED_OFFICE_RULES.filter(r => !seen.includes(r));
    expect.soft(
      missingOffice,
      `Office_* rules expected to fire but didn't: ${missingOffice.join(', ')}`,
    ).toEqual([]);

    // ── 4. Structural baseline still anchors ─────────────────────────
    // These two were already firing on `example.docm` pre-fixture;
    // assert here so a regression that suppressed them on the new
    // fixture (e.g. magic-gate change) surfaces immediately.
    expect(seen).toContain('Office_Macro_Project_Present');
    expect(seen).toContain('PPAM_PPTM_AddIn');

    // ── 5. Risk floor ─────────────────────────────────────────────────
    // Multiple critical-severity rules (VBA_Shell_Execution,
    // VBA_Download_Capability, VBA_PowerShell_Invocation,
    // VBA_Scheduled_Task_Persistence, VBA_MSHTA_Invocation,
    // VBA_Certutil_Decode, VBA_NewObject_PowerShell,
    // Office_Remote_Template_Injection) ⇒
    // `escalateRisk(findings, 'critical')`. A regression that
    // ratcheted this back to 'high' or below would mean the rule
    // cluster lost its critical severities.
    expect(isRiskAtLeast(findings.risk, 'critical')).toBe(true);
  });
});
