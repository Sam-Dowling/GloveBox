// ════════════════════════════════════════════════════════════════════════════
// forensics.spec.ts — Smoke for Timeline-routed fixtures (EVTX, PCAP,
// SQLite, CSV, TSV).
//
// These formats route to the `Timeline` view rather than the
// `Findings` panel — `app.findings` stays `null` by design. The test
// API's `dumpFindings()` therefore returns an empty projection
// (risk=null, iocCount=0, ...). To assert that the file actually
// loaded we read `dumpResult()` and check `bufferLength` plus the
// dispatched filename.
//
// EVTX and PCAP are *hybrid* Timeline routes — the parser runs in the
// timeline worker, but the analyser (`EvtxDetector.analyzeForSecurity`
// / `PcapRenderer._analyzePcapInfo`) runs on the main thread because
// it touches `pushIOC` / `IOC.*` / `escalateRisk` globals that aren't
// in the worker bundle. Either way the analyser's findings go to a
// side-channel (`_evtxFindings` / `_pcapFindings`) consumed by the ⚡
// Summarize button, NOT to `app.findings`.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  dumpResult,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

test.describe('forensics / Timeline-routed renderers', () => {
  const ctx = useSharedBundlePage();

  // ── Helper: load + assert the Timeline route was taken (`timeline:
  //   true` in the synthetic dumpResult shape) and the file actually
  //   parsed (`timelineRowCount > 0` or `bufferLength > 0`). Returns
  //   the dumpResult so callers can pin format-specific fields
  //   (e.g. `formatTag === 'PCAP'` for the hybrid PCAP route).
  async function assertTimelineLoaded(relPath: string) {
    const findings = await loadFixture(ctx.page, relPath);
    // findings should be a well-formed empty projection — Timeline
    // route does not populate the findings panel.
    expect(findings.iocCount).toBe(0);
    expect(findings.externalRefCount).toBe(0);
    expect(findings.risk).toBeNull();
    const result = await dumpResult(ctx.page);
    expect(result).not.toBeNull();
    expect(result!.timeline).toBe(true);
    expect(result!.filename).not.toBeNull();
    // Either rows landed or at least the original file is held — both
    // are positive evidence that the Timeline mount happened.
    expect(
      (result!.timelineRowCount || 0) > 0
      || (result!.bufferLength || 0) > 0,
    ).toBe(true);
    return result!;
  }

  test('EVTX security log loads via Timeline', async () => {
    await assertTimelineLoaded('examples/forensics/example-security.evtx');
  });

  test('EVTX system log loads via Timeline', async () => {
    await assertTimelineLoaded('examples/forensics/example.evtx');
  });

  test('PCAP libpcap capture loads via Timeline (hybrid route)', async () => {
    // PCAP joins EVTX as the second hybrid Timeline route: the parser
    // runs in the timeline worker (`_parsePcap` → `PcapRenderer._parse`
    // → packet rows streamed via `_makeRowStreamer`), but the analyser
    // (`PcapRenderer._analyzePcapInfo`) runs on the main thread because
    // it pushes IOCs through `pushIOC` / `IOC.*` / `escalateRisk` —
    // globals that don't exist in the worker bundle. The analyser's
    // findings land on the TimelineView's `_pcapFindings` side-channel
    // (driving the ⚡ Summarize button), NOT on `app.findings`. The
    // standard `assertTimelineLoaded` checks (timeline:true, no IOCs in
    // findings, rows landed) confirm both halves of the contract are
    // wired correctly. The Timeline `formatLabel` is the stable tag
    // `'PCAP'` so the snapshot-matrix `formatTag` assertion at
    // expected.jsonl:56 is variant-stable across libpcap/PCAPNG.
    const result = await assertTimelineLoaded('examples/forensics/example-capture.pcap');
    expect(result.formatTag).toBe('PCAP');
    // Sanity: the worker streamed packet rows. The fixture has ~10s of
    // captured traffic; pin to a strictly positive count to catch
    // silent zero-row escapes back to the legacy card view.
    expect((result.timelineRowCount || 0)).toBeGreaterThan(0);

    // Schema-driven GeoIP enrichment on BOTH endpoints. The TimelineView
    // ctor's `ipColumns` hint (sourced from
    // `PcapRenderer.TIMELINE_IP_COL_INDICES = [2, 4]`) makes
    // `_detectIpColumns()` short-circuit past the heuristic 80%-IPv4
    // sample scan, so even mixed v4/v6 captures or sparse traffic
    // (where the heuristic gate fails on one or both columns) still
    // produce `Source.geo` AND `Destination.geo`. Wait for both
    // enrichment columns to land — the geoip pass runs at +100 ms
    // post-mount and re-runs once `_app` is wired by the router, so
    // 5 s is generous on cold CI.
    await ctx.page.waitForFunction(() => {
      const w = window as unknown as {
        app: { _timelineCurrent?: { _extractedCols?: Array<{ name?: string; kind?: string }> } };
      };
      const tl = w.app && w.app._timelineCurrent;
      if (!tl || !Array.isArray(tl._extractedCols)) return false;
      const geoNames = tl._extractedCols
        .filter(e => e && e.kind === 'geoip')
        .map(e => e!.name || '');
      return geoNames.includes('Source.geo')
          && geoNames.includes('Destination.geo');
    }, null, { timeout: 5_000 });
  });

  test('Chrome history SQLite loads via Timeline', async () => {
    // Chrome's `History` schema is recognised by the SQLite Timeline
    // factory and routes via Timeline (formatLabel = "SQLite – Chrome
    // History"). The generic `example.sqlite` below uses an unknown
    // schema and falls back to the regular renderer.
    await assertTimelineLoaded('examples/forensics/chromehistory-example.sqlite');
  });

  test('generic SQLite falls back to regular analyser (zero-row escape)', async () => {
    // Documented in `_loadFileInTimeline` at src/app/timeline/timeline-router.js:240
    // — when the SQLite factory yields zero usable rows the route
    // unwinds and re-runs the regular analyser pipeline. Lock the
    // resulting findings shape so a future Timeline schema-pack
    // regression doesn't silently swallow this fixture.
    const findings = await loadFixture(ctx.page, 'examples/forensics/example.sqlite');
    // The generic SQLite renderer extracts URLs / IPs from the page
    // bodies as plain text. We don't pin the exact count — just that
    // the regular path actually fired and found *something*.
    expect(findings.iocCount).toBeGreaterThan(0);
    expect(findings.iocTypes).toContain('URL');
    const result = await dumpResult(ctx.page);
    expect(result).not.toBeNull();
    // The fallback path stamps `currentResult` — `timeline` should
    // be `false`, NOT the synthetic Timeline shape.
    expect(result!.timeline).toBe(false);
  });

  test('JSON-shaped CSV loads via Timeline', async () => {
    await assertTimelineLoaded('examples/forensics/json-example.csv');
  });

  test('Apache CLF .log loads via Timeline', async () => {
    // `.log` is space-delimited Apache / Nginx Common (or Combined)
    // Log Format. The Timeline router passes `kindHint: 'log'` so the
    // CSV worker uses a dedicated CLF tokeniser (handles backslash-
    // escaped quotes that RFC4180 mishandles), then synthesises
    // canonical column names (`ip ident auth time request status
    // bytes referer user_agent`). See `_tlTokenizeClfLine` in
    // `src/app/timeline/timeline-helpers.js`.
    await assertTimelineLoaded('examples/forensics/apache-access-example.log');
  });
});
