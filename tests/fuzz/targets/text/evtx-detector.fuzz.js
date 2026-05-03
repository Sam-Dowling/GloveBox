'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/text/evtx-detector.fuzz.js
//
// Fuzz the EVTX detector's pure pieces:
//   • EvtxDetector._parseEventDataPairs(eventData)
//     Pure string→{key,val}[] tokenizer. Used per-event, ~1M events
//     plausible per file, so any superlinear behaviour here is a real
//     hot-path bug.
//   • EvtxDetector.analyzeForSecurity(buf, name, prebuiltEvents)
//     Driven via the `prebuiltEvents` shortcut so we never touch the
//     EvtxRenderer (which needs DOM document for some output paths).
//     Fuzzer constructs a small synthetic events[] from the input bytes
//     — random-but-deterministic — and asserts the analyser returns
//     well-shaped findings without throwing.
//
// History:
//   • 9b10618 — align _evtxEvents to truncated row count on sync EVTX path
//   • 369c8e9 — aggregate budget across drill-down
//   • 484d23d — byte offsets must map through the actual scanned buffer
//
// Invariants:
//   1. _parseEventDataPairs never throws for any string input.
//   2. analyzeForSecurity returns an object with `risk` ∈ {safe..critical}
//      and arrays for `externalRefs` etc.
//   3. No emitted external-ref has type outside IOC.*.
// ════════════════════════════════════════════════════════════════════════════

const path = require('node:path');
const { defineFuzzTarget } = require('../../helpers/harness.js');
const { syntheticTextSeeds } = require('../../helpers/seed-corpus.js');

const td = new TextDecoder('utf-8', { fatal: false });
const VALID_RISK = new Set(['safe', 'low', 'medium', 'high', 'critical']);
const VALID_IOC = new Set();

// Build a synthetic events array from input bytes. The shape mirrors
// EvtxRenderer._parse() output so analyzeForSecurity gets exactly what
// it expects — but the field VALUES are fuzzer-controlled.
function synthEvents(text, IOC_unused) {
  const lines = text.split('\n').slice(0, 256);
  const evs = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Format: "<eid>|<provider>|<channel>|<computer>|<eventData>"
    // missing fields default to empty.
    const parts = line.split('|');
    const eid = parseInt(parts[0], 10);
    evs.push({
      eventId: Number.isFinite(eid) ? eid : (i % 5000),
      provider: parts[1] || '',
      channel: parts[2] || '',
      computer: parts[3] || '',
      eventData: parts[4] || '',
      timestamp: '',
    });
  }
  return evs;
}

const fuzz = defineFuzzTarget({
  modules: ['src/constants.js', 'src/evtx-detector.js'],
  expose: ['IOC', 'EvtxDetector'],
  maxBytes: 256 * 1024,
  perIterBudgetMs: 2_500,

  onIteration(ctx, data) {
    const { IOC, EvtxDetector } = ctx;
    if (!EvtxDetector) throw new Error('harness: EvtxDetector not exposed');
    if (VALID_IOC.size === 0) for (const v of Object.values(IOC)) VALID_IOC.add(v);

    const text = td.decode(data);
    if (text.length === 0) return;

    // ── Sub-target 1: _parseEventDataPairs ──────────────────────────
    // Drive with the raw text and a few common delimiters.
    {
      const pairs = EvtxDetector._parseEventDataPairs(text);
      if (!Array.isArray(pairs)) {
        throw new Error(`invariant: _parseEventDataPairs returned ${typeof pairs}`);
      }
      for (const p of pairs) {
        if (!p || typeof p !== 'object') {
          throw new Error('invariant: pair not object');
        }
        if (typeof p.key !== 'string') {
          throw new Error(`invariant: pair.key not string — ${typeof p.key}`);
        }
        if (typeof p.val !== 'string') {
          throw new Error(`invariant: pair.val not string — ${typeof p.val}`);
        }
      }
    }

    // ── Sub-target 2: analyzeForSecurity via prebuiltEvents ─────────
    const events = synthEvents(text, IOC);
    // The first arg is `buffer`; the analyser only consults it when
    // `prebuiltEvents` is empty/undefined. We pass a tiny placeholder
    // buffer to satisfy `new Uint8Array(buffer)` at the top of the
    // function.
    const findings = EvtxDetector.analyzeForSecurity(
      new Uint8Array(0).buffer,
      'fuzz.evtx',
      events,
    );

    if (!findings || typeof findings !== 'object') {
      throw new Error('invariant: analyzeForSecurity returned non-object');
    }
    if (typeof findings.risk !== 'string' || !VALID_RISK.has(findings.risk)) {
      throw new Error(`invariant: findings.risk ${JSON.stringify(findings.risk)} invalid`);
    }
    if (!Array.isArray(findings.externalRefs)) {
      throw new Error('invariant: findings.externalRefs not array');
    }
    for (const r of findings.externalRefs) {
      if (!r || typeof r !== 'object') {
        throw new Error('invariant: externalRef not object');
      }
      if (r.type !== undefined && !VALID_IOC.has(r.type)) {
        throw new Error(`invariant: externalRef.type ${JSON.stringify(r.type)} not in IOC.*`);
      }
    }
  },
});

const handRolled = [
  '4624|Microsoft-Windows-Security-Auditing|Security|HOST|TargetUserName=admin | LogonType=3',
  '1|Microsoft-Windows-Sysmon|Sysmon|HOST|Image=C:\\Windows\\System32\\cmd.exe | CommandLine=cmd /c whoami | Hashes=SHA1=abc,MD5=def',
  '7045|Service Control Manager|System|HOST|ServiceName=evil | ImagePath=\\\\?\\C:\\windows\\temp\\x.exe',
  '|||',
  'A=B | C=D | E=F',
  // Adversarial: extreme key length ( > 60 chars triggers the "no-key" branch )
  ('K'.repeat(70)) + '=value',
  // Adversarial: many pipes
  'a'.repeat(100) + ' | ' + 'b'.repeat(100),
];
const seeds = [
  Buffer.from(handRolled.join('\n'), 'utf8'),
  ...syntheticTextSeeds(8),
];

module.exports = { fuzz, seeds, name: 'evtx-detector' };
