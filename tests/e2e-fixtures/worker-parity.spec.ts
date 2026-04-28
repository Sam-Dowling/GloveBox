// ════════════════════════════════════════════════════════════════════════════
// worker-parity.spec.ts — Cross-thread parity for the IOC-extract
// pipeline.
//
// `WorkerManager.runIocExtract(text, opts)` and the synchronous
// `extractInterestingStringsCore(text, opts)` MUST produce
// byte-equivalent output (modulo `parseMs`). The host falls back to
// the synchronous shim on any worker-side rejection (worker
// unavailable / supersession / watchdog timeout / postMessage error)
// — see `src/app/app-load.js:_kickIocExtractWorker`. A divergence
// between the two paths means the file ingress goes through one
// extractor when the worker is healthy and a different extractor
// when it isn't, silently changing the IOC set on a heisen-fault.
// This spec catches that.
//
// Approach: load a fixture's text inside the page realm, run BOTH
// paths back-to-back, then JSON-compare the returned findings
// arrays.
//
// We avoid loading a fixture through `loadFixture` because that
// triggers the full `_loadFile` chain (renderer dispatch, sidebar
// rebuild, YARA scan, etc.) — we only want to exercise the
// extractor in isolation. The fixture text is read host-side and
// forwarded as a string into both code paths.
// ════════════════════════════════════════════════════════════════════════════

import * as fs from 'node:fs';
import * as path from 'node:path';
import { test, expect } from '@playwright/test';
import { REPO_ROOT, useSharedBundlePage } from '../helpers/playwright-helpers';

interface ParityRow {
  type: string;
  url: string;
  severity?: string;
}

// Compare two findings arrays for structural equality, ignoring
// non-deterministic side-channel fields (`_sourceOffset`,
// `_sourceLength`, `_highlightText`) that are pure render hints.
function canonicalise(rows: any[]): ParityRow[] {
  return rows
    .map(r => ({
      type: String(r.type || ''),
      url: String(r.url || ''),
      severity: r.severity || undefined,
    }))
    .sort((a, b) => {
      if (a.type !== b.type) return a.type < b.type ? -1 : 1;
      if (a.url !== b.url) return a.url < b.url ? -1 : 1;
      return 0;
    });
}

// Anchor fixtures cover three extractor regimes:
//   • Plain ASCII text with defanged IOCs (URL/email/IPv4 refang).
//   • Mixed obfuscation with stacked encodings (the heaviest text
//     fixture — exercises the regex chain end-to-end).
//   • Phishing email body (URLs + emails + Received header IPs).
const PARITY_FIXTURES = [
  'examples/encoded-payloads/defanged-iocs.txt',
  'examples/encoded-payloads/mixed-obfuscations.txt',
  'examples/encoded-payloads/example-safelinks.txt',
];

test.describe('IOC-extract worker ↔ host parity', () => {
  const ctx = useSharedBundlePage();

  for (const rel of PARITY_FIXTURES) {
    test(`${rel} — worker output matches host output`, async () => {
      const page = ctx.page;
      const abs = path.join(REPO_ROOT, rel);
      const text = fs.readFileSync(abs, 'utf-8');

      // Run the host shim and the worker side-by-side and return
      // both findings arrays plus availability. The worker may not
      // be available in some Playwright configurations
      // (`workersAvailable()` checks blob: URL spawn) — skip the
      // assertion in that case so the spec doesn't false-fail on
      // an environment that's already going to use the host
      // fallback for everything anyway.
      const result = await page.evaluate(async (text: string) => {
        const w = window as unknown as {
          extractInterestingStringsCore: (
            t: string,
            o: Record<string, unknown>,
          ) => { findings: any[] };
          WorkerManager: {
            workersAvailable(): boolean;
            runIocExtract(
              t: string,
              o: Record<string, unknown>,
            ): Promise<{ findings: any[] }>;
          };
        };
        // Sync host path.
        const hostOut = w.extractInterestingStringsCore(text, {
          existingValues: [],
          vbaModuleSources: [],
        });
        // Worker path. Skip when blob: workers aren't usable.
        const workersOk = w.WorkerManager.workersAvailable();
        let workerOut = null;
        if (workersOk) {
          workerOut = await w.WorkerManager.runIocExtract(text, {
            existingValues: [],
            vbaModuleSources: [],
          });
        }
        return {
          workersOk,
          hostFindings: hostOut.findings,
          workerFindings: workerOut ? workerOut.findings : null,
        };
      }, text);

      // We deliberately don't assert `hostFindings.length > 0` per
      // fixture — `mixed-obfuscations.txt` for example has IOCs that
      // surface only via `EncodedContentDetector` and YARA, not the
      // pure-regex extractor. Parity holds even when both paths
      // return empty: the test still proves the worker matches the
      // host, just trivially.

      if (!result.workersOk) {
        test.skip(true, 'WorkerManager.workersAvailable() returned false; '
          + 'parity check requires worker support');
        return;
      }
      expect(result.workerFindings).not.toBeNull();
      const hostCanon = canonicalise(result.hostFindings);
      const workerCanon = canonicalise(result.workerFindings!);
      expect(workerCanon).toEqual(hostCanon);
    });
  }
});
