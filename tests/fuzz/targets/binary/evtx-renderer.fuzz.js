'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/binary/evtx-renderer.fuzz.js
//
// Fuzz `EvtxRenderer.prototype._parse(bytes)` — the binary EVTX walker.
//
// Why _parse and not analyzeForSecurity? `EvtxRenderer.analyzeForSecurity`
// is a 1-line delegate to `EvtxDetector.analyzeForSecurity` which is
// already exercised by `targets/text/evtx-detector.fuzz.js` (via the
// prebuiltEvents shortcut). The genuinely-new coverage here is the
// *binary* EVTX file-format parser: 4096-byte file header → 64 KiB chunk
// loop → BinXml record decoder → template + string-table cross-refs.
//
// Unlike PE/ELF/Mach-O's analyzeForSecurity (try/catch wrapped),
// `_parse` throws on bad magic and on length-field OOB. We narrow
// `isExpectedError` to the documented hard-fail messages.
//
// The result is the events array directly: an array of `{ eventId,
// channel, provider, computer, eventData, timestamp }` records — same
// shape EvtxDetector.analyzeForSecurity consumes via prebuiltEvents.
// ════════════════════════════════════════════════════════════════════════════

const { defineFuzzTarget } = require('../../helpers/harness.js');
const { loadSeeds } = require('../../helpers/seed-corpus.js');

const fuzz = defineFuzzTarget({
  modules: [
    'src/constants.js',
    'src/evtx-event-ids.js',
    'src/evtx-detector.js',
    'src/renderers/evtx-renderer.js',
  ],
  expose: ['IOC', 'EvtxRenderer', 'EvtxDetector'],

  maxBytes: 8 * 1024 * 1024,
  perIterBudgetMs: 5_000,

  isExpectedError(err) {
    if (!err || typeof err.message !== 'string') return false;
    // Hard-fail validation paths inside _parse — not bugs.
    if (err.message.startsWith('Not a valid EVTX file')) return true;
    if (err.message.startsWith('parser-limit:')) return true;
    return false;
  },

  onIteration(ctx, data) {
    const { EvtxRenderer } = ctx;
    if (!EvtxRenderer) throw new Error('harness: EvtxRenderer not exposed');

    const r = new EvtxRenderer();
    const bytes = new Uint8Array(
      data.buffer, data.byteOffset, data.byteLength,
    );

    let events;
    try {
      events = r._parse(bytes);
    } catch (e) {
      // isExpectedError filters known-good failure modes; anything else
      // re-throws and is caught by the harness.
      throw e;
    }

    // Shape invariants — only enforced when _parse succeeds. _parse
    // returns the events array directly (NOT a wrapper object).
    if (!Array.isArray(events)) {
      throw new Error(`invariant: _parse returned ${typeof events} (expected array)`);
    }
    for (const ev of events) {
      if (!ev || typeof ev !== 'object') {
        throw new Error('invariant: event entry not object');
      }
      // eventId may be a string (rare path) or number; tolerate both.
      if (ev.eventId !== undefined
          && typeof ev.eventId !== 'number'
          && typeof ev.eventId !== 'string') {
        throw new Error(`invariant: event.eventId ${typeof ev.eventId}`);
      }
      for (const k of ['channel', 'provider', 'computer', 'eventData']) {
        if (ev[k] !== undefined && typeof ev[k] !== 'string') {
          throw new Error(`invariant: event.${k} not string (got ${typeof ev[k]})`);
        }
      }
    }
  },
});

const seeds = loadSeeds({
  dirs: ['forensics'],
  extensions: ['evtx'],
  perFileMaxBytes: 2 * 1024 * 1024,
  totalMaxBytes: 8 * 1024 * 1024,
  maxSeeds: 8,
});

// Synthetic minimal EVTX header: "ElfFile\0" magic + chunkCount=0 at
// 0x28. 4096 bytes total (file header only, no chunks). Drives the
// "valid header, zero chunks" early-return path.
function syntheticMinimalEvtx() {
  const buf = Buffer.alloc(4096);
  buf.write('ElfFile\0', 0, 'binary');
  // chunkCount @ 0x28 = 0 (already zero)
  return buf;
}

seeds.push(syntheticMinimalEvtx());

module.exports = { fuzz, seeds, name: 'evtx-renderer' };
