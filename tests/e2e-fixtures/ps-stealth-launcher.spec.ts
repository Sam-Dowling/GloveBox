// ════════════════════════════════════════════════════════════════════════════
// ps-stealth-launcher.spec.ts — End-to-end coverage for the
// PowerShell stealth-flag / credential-access / fileless-persistence
// rule cluster.
//
// `examples/windows-scripts/ps-stealth-launcher.ps1` is a HARMLESS
// fixture that aggregates ~10 indicator strings across the
// `script-threats.yar` rule pack. Before this fixture existed, every
// `PowerShell_*` rule below the obfuscation/encoded-command tier was
// unanchored — the corpus contained the rules but no fixture proved
// they fired, so a regression that broke the rule body or its
// `applies_to` gate would ship silently. See
// `tests/e2e-fixtures/yara-rules-coverage.spec.ts` for the
// complementary coverage walk.
//
// What this spec proves:
//   1. The fixture sniffs as `formatTag === 'ps1'` (NOT `'bash'` —
//      the bash sniffer's command-substitution backtick rule
//      previously won this fixture's score race; the file's leading
//      `<#…#>` block-comment header + `[CmdletBinding()]` +
//      `Set-StrictMode` markers exist specifically to flip the
//      `_sniffScriptKind` outcome to `ps1`).
//   2. All ten target PowerShell_* rules fire on this fixture.
//      Listing them explicitly here (not just relying on
//      `expected.jsonl`'s family-anchor sample of three) gives a
//      fast, focused regression signal — losing any one of them
//      points at a single rule body or its `applies_to` predicate.
//   3. The risk floor escalates to 'critical' (multiple critical-
//      severity rules ⇒ `escalateRisk(findings, 'critical')`).
//
// Why one spec instead of relying on `snapshot-matrix.spec.ts`:
//   The matrix pins at most three "family-anchor" rules per fixture
//   (intentional — see `scripts/gen_expected.py` header). This spec
//   pins the FULL ten-rule cluster so the rule pack as a system has
//   visible regression coverage, not just the first three sorted
//   alphabetically.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  dumpResult,
  ruleNames,
  isRiskAtLeast,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

// The full set of PowerShell_* rules this fixture is designed to
// anchor. Ordering matches the rule definitions in
// `src/rules/script-threats.yar` for ease of cross-reference.
const TARGETED_RULES = [
  'AMSI_ETW_Bypass',
  'PowerShell_Reflective_Load',
  'PowerShell_Execution_Policy_Bypass',
  'PowerShell_Hidden_Window',
  'PowerShell_Credential_Theft',
  'PowerShell_Certutil_Combo',
  'PowerShell_AddType_Inline_CSharp',
  'PowerShell_Invoke_Command_Remote',
  'PowerShell_Stealth_Flags_Combo',
  'PowerShell_WMI_Event_Persistence',
];

test.describe('PowerShell stealth-launcher (script-threats.yar cluster)', () => {
  const ctx = useSharedBundlePage();

  test('ps-stealth-launcher.ps1 anchors the full PowerShell rule cluster', async () => {
    const findings = await loadFixture(
      ctx.page, 'examples/windows-scripts/ps-stealth-launcher.ps1');
    const result = await dumpResult(ctx.page);

    // ── 1. Sniffer pin ────────────────────────────────────────────────
    // `formatTag === 'ps1'` is what unlocks every rule whose meta
    // header reads `applies_to = "ps1, plaintext, decoded-payload"`.
    // A regression that demotes this fixture to `'bash'` (an
    // ambiguous-tie outcome, see `_sniffScriptKind` scoring) would
    // silently zero out the cluster below — explicit pin.
    expect(result?.timeline ?? false).toBe(false);
    expect(result?.formatTag).toBe('ps1');

    // ── 2. Rule cluster ───────────────────────────────────────────────
    // Every targeted rule must fire. `expect.soft` so a single
    // missing rule surfaces every other gap in the same run rather
    // than masking N-1 failures behind the first.
    const seen = ruleNames(findings);
    const missing = TARGETED_RULES.filter(r => !seen.includes(r));
    expect.soft(
      missing,
      `rules expected to fire but didn't: ${missing.join(', ')}`,
    ).toEqual([]);

    // ── 3. Risk floor ─────────────────────────────────────────────────
    // Multiple critical-severity rules (Credential_Theft,
    // AddType_Inline_CSharp, Invoke_Command_Remote, Stealth_Flags_Combo,
    // WMI_Event_Persistence, AMSI_Bypass, Reflective_Load,
    // Certutil_Combo) ⇒ `escalateRisk(findings, 'critical')`. A
    // regression that ratcheted this back to 'high' or below would
    // mean the rule cluster lost its critical severities.
    expect(isRiskAtLeast(findings.risk, 'critical')).toBe(true);
  });
});
