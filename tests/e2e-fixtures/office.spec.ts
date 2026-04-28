// ════════════════════════════════════════════════════════════════════════════
// office.spec.ts — Smoke coverage for the Office renderer family.
//
//   • Modern OOXML: docx / xlsx / pptx / xlsm / pptm / docm
//   • Legacy CFB: doc / xls / ppt
//   • OpenDocument: odt / ods / odp
//   • Web-bait: iqy (Excel web query), slk (symbolic link)
//   • Free-text: rtf
//   • Tabular passthrough: csv / tsv (both route to Timeline)
//
// Anchor invariants:
//   1. Macro-bearing OOXML (docm / xlsm / pptm) fire
//      `Office_Macro_Project_Present` and (where applicable)
//      `PPAM_PPTM_AddIn`.
//   2. RTF surfaces the `Standalone_RTF_Obfuscation` cluster.
//   3. .iqy and .slk exhibit critical/high risk and surface the
//      respective `IQY_Web_Query_File` / `SLK_Symbolic_Link_File`
//      anchor rules.
//   4. Benign xlsx / xls / pptx exhibit zero IOCs and stay at 'low'.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  dumpResult,
  isRiskAtLeast,
  ruleNames,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

test.describe('Office (OOXML / CFB / OpenDocument)', () => {
  const ctx = useSharedBundlePage();

  test('benign .docx parses cleanly', async () => {
    const findings = await loadFixture(ctx.page, 'examples/office/example.docx');
    expect(findings.iocTypes).toContain('URL');
  });

  test('macro-bearing .docm fires Office_Macro_Project_Present', async () => {
    const findings = await loadFixture(ctx.page, 'examples/office/example.docm');
    expect(ruleNames(findings)).toContain('Office_Macro_Project_Present');
    expect(isRiskAtLeast(findings.risk, 'high')).toBe(true);
  });

  test('macro-bearing .xlsm fires Office_Macro_Project_Present', async () => {
    const findings = await loadFixture(ctx.page, 'examples/office/example.xlsm');
    expect(ruleNames(findings)).toContain('Office_Macro_Project_Present');
    expect(isRiskAtLeast(findings.risk, 'high')).toBe(true);
  });

  test('macro-bearing .pptm fires Office_Macro_Project_Present + PPAM_PPTM_AddIn', async () => {
    const findings = await loadFixture(ctx.page, 'examples/office/example.pptm');
    const rules = ruleNames(findings);
    expect(rules).toContain('Office_Macro_Project_Present');
    expect(rules).toContain('PPAM_PPTM_AddIn');
    expect(isRiskAtLeast(findings.risk, 'high')).toBe(true);
  });

  test('benign .xlsx is clean', async () => {
    const findings = await loadFixture(ctx.page, 'examples/office/example.xlsx');
    expect(findings.iocCount).toBe(0);
    expect(findings.risk).toBe('low');
  });

  test('benign .pptx is clean', async () => {
    const findings = await loadFixture(ctx.page, 'examples/office/example.pptx');
    expect(findings.iocCount).toBe(0);
    expect(findings.risk).toBe('low');
  });

  test('legacy .doc fires MSI_Network_Indicators / Embedded_ZIP rules', async () => {
    const findings = await loadFixture(ctx.page, 'examples/office/example.doc');
    const rules = ruleNames(findings);
    expect(rules).toContain('Embedded_Compressed_Stream');
    expect(rules.some(r => /MSI_Network_Indicators|Embedded_ZIP/.test(r))).toBe(true);
  });

  test('legacy .ppt fires Embedded_Compressed_Stream', async () => {
    const findings = await loadFixture(ctx.page, 'examples/office/example.ppt');
    expect(ruleNames(findings)).toContain('Embedded_Compressed_Stream');
  });

  test('legacy .xls (clean) parses with no IOCs', async () => {
    const findings = await loadFixture(ctx.page, 'examples/office/example.xls');
    expect(findings.iocCount).toBe(0);
    expect(findings.risk).toBe('low');
  });

  test('OpenDocument .odt fires Embedded_Compressed_Stream', async () => {
    const findings = await loadFixture(ctx.page, 'examples/office/example.odt');
    expect(ruleNames(findings)).toContain('Embedded_Compressed_Stream');
  });

  test('OpenDocument .ods fires Embedded_Compressed_Stream', async () => {
    const findings = await loadFixture(ctx.page, 'examples/office/example.ods');
    expect(ruleNames(findings)).toContain('Embedded_Compressed_Stream');
  });

  test('OpenDocument .odp fires Embedded_Compressed_Stream', async () => {
    const findings = await loadFixture(ctx.page, 'examples/office/example.odp');
    expect(ruleNames(findings)).toContain('Embedded_Compressed_Stream');
  });

  test('IQY (Excel web query) escalates to critical', async () => {
    const findings = await loadFixture(ctx.page, 'examples/office/example.iqy');
    expect(isRiskAtLeast(findings.risk, 'critical')).toBe(true);
    expect(ruleNames(findings)).toContain('IQY_Web_Query_File');
  });

  test('SLK (symbolic link) escalates and fires SLK rule', async () => {
    const findings = await loadFixture(ctx.page, 'examples/office/example.slk');
    expect(isRiskAtLeast(findings.risk, 'high')).toBe(true);
    expect(ruleNames(findings)).toContain('SLK_Symbolic_Link_File');
  });

  test('RTF fires Standalone_RTF_Obfuscation', async () => {
    const findings = await loadFixture(ctx.page, 'examples/office/example.rtf');
    expect(ruleNames(findings)).toContain('Standalone_RTF_Obfuscation');
    expect(isRiskAtLeast(findings.risk, 'medium')).toBe(true);
  });

  test('CSV routes to Timeline (no findings panel)', async () => {
    const findings = await loadFixture(ctx.page, 'examples/office/example.csv');
    expect(findings.iocCount).toBe(0);
    expect(findings.risk).toBeNull();
    const result = await dumpResult(ctx.page);
    expect(result).not.toBeNull();
    expect(result!.timeline).toBe(true);
  });

  test('TSV routes to Timeline (no findings panel)', async () => {
    const findings = await loadFixture(ctx.page, 'examples/office/example.tsv');
    expect(findings.iocCount).toBe(0);
    expect(findings.risk).toBeNull();
    const result = await dumpResult(ctx.page);
    expect(result).not.toBeNull();
    expect(result!.timeline).toBe(true);
  });

  // Regression coverage for the multi-line-quoted-cell parser bug
  // (https://example.com — pre-refactor, the line-oriented parser split
  // every `\n` into a fresh row and pushed quoted-cell continuations
  // into column 0 of a phantom next row). The fixture has 27 physical
  // lines but exactly 4 logical rows (1 header + 3 body) once
  // RFC-4180 quoting is honoured. The Timeline excludes the header,
  // so we expect exactly 3 rows.
  test('TSV with multi-line quoted cells parses to 3 logical body rows', async () => {
    const findings = await loadFixture(ctx.page, 'examples/office/example-multiline.tsv');
    expect(findings.iocCount).toBe(0);
    const result = await dumpResult(ctx.page);
    expect(result).not.toBeNull();
    expect(result!.timeline).toBe(true);
    // The header has 13 columns; bodies are ragged (8/9/11 cols) and
    // contain literal `\n` inside quoted cells. The legacy parser
    // would have produced 26 rows here.
    expect(result!.timelineRowCount).toBe(3);
  });
});
