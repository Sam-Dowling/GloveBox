'use strict';
// ════════════════════════════════════════════════════════════════════════════
// archive-budget.js — aggregate archive-expansion budget (PLAN H5)
//
// Each archive renderer enforces its own per-archive caps via
// `PARSER_LIMITS.MAX_ENTRIES` (10 k rows) and the per-entry compression-ratio
// check. Those caps are *single-renderer* invariants: one ZIP central
// directory cannot enumerate more than 10 k rows. They do nothing about the
// **recursive drill-down** case where a top-level ZIP contains a JAR that
// contains an MSIX that contains a 7z — each level individually within its
// own cap, but the user's memory and patience burn through the chain.
//
// `ArchiveBudget` closes that gap by aggregating across every archive
// renderer in the recursion. One budget per top-level load (reset by
// `App._handleFiles`, NOT by drill-down loads — the recursion intentionally
// shares a single budget). When either cap trips, archive renderers stop
// appending rows, set their local `truncated` flag, and surface a single
// `IOC.INFO` row in the sidebar pointing at the cap that fired.
//
// The two caps live in `PARSER_LIMITS` (constants.js) and are deliberately
// generous so legitimate fat archives aren't false-positively truncated:
//   * `MAX_AGGREGATE_ENTRIES`           (default 50 000)
//   * `MAX_AGGREGATE_DECOMPRESSED_BYTES` (default 256 MiB)
//
// Contract:
//   * `reset()` — call once per top-level load. Restores the budget to
//     full and clears any prior `reason`. Drill-downs MUST NOT call this.
//   * `consume(n, bytes)` — call before pushing each archive row.
//     Returns `true` when the budget is still healthy, `false` once it has
//     just become exhausted (or was already exhausted). The first call
//     that causes exhaustion latches `reason` to a short human-readable
//     string; subsequent calls keep the same string so the row count
//     surfaced to the analyst is the row that actually triggered the cap.
//   * `exhausted` (getter) — boolean.
//   * `reason`    (getter) — string; empty when not exhausted.
//
// Usage pattern in an archive renderer:
//
//   const budget = app && app._archiveBudget;
//   for (const e of centralDir) {
//     if (budget && !budget.consume(1, e.uncompressedSize | 0)) {
//       truncated = true;
//       break;
//     }
//     entries.push(...);
//   }
//   if (truncated && budget && budget.exhausted) {
//     pushIOC(findings, { type: IOC.INFO, value: budget.reason, severity: 'info' });
//   }
//
// The class is deliberately tiny — no event emitters, no listener machinery.
// The only state is `_entries`, `_bytes`, `_reason`. Renderers consult it
// inline; they own the IOC.INFO surfacing because the wording differs by
// container ("ZIP central directory truncated" vs. "7z entry stream
// truncated"). The shared *content* of the IOC.INFO comes from `reason`.
// ════════════════════════════════════════════════════════════════════════════

class ArchiveBudget {
  constructor() {
    this._entries = 0;
    this._bytes = 0;
    this._reason = '';
  }

  reset() {
    this._entries = 0;
    this._bytes = 0;
    this._reason = '';
  }

  /**
   * Account for a single about-to-be-pushed archive row.
   * @param {number} entries  number of entries (typically 1)
   * @param {number} bytes    declared uncompressed size (defensive: 0 if unknown)
   * @returns {boolean}       true → still under budget, push the row.
   *                          false → exhausted, do NOT push. The caller
   *                                  should set its local `truncated` flag,
   *                                  break the enumeration loop, and surface
   *                                  `this.reason` as a single `IOC.INFO`
   *                                  row.
   */
  consume(entries, bytes) {
    if (this._reason) return false;       // already exhausted — short-circuit.
    const e = (entries | 0) > 0 ? (entries | 0) : 0;
    const b = Number.isFinite(bytes) && bytes > 0 ? Math.floor(bytes) : 0;
    const limits = (typeof PARSER_LIMITS !== 'undefined' && PARSER_LIMITS) || {};
    const capE = limits.MAX_AGGREGATE_ENTRIES           || 50_000;
    const capB = limits.MAX_AGGREGATE_DECOMPRESSED_BYTES || (256 * 1024 * 1024);

    // Tentatively advance the counters. If either cap is breached we latch
    // `_reason` and reject the row. We deliberately do NOT roll the
    // counters back — once a cap fires the budget stays exhausted for the
    // rest of the load, which is the whole point.
    this._entries += e;
    this._bytes   += b;

    if (this._entries > capE) {
      this._reason =
        `Aggregate archive-entry budget exhausted at ${capE.toLocaleString()} entries — ` +
        `further nested-archive rows skipped to bound memory.`;
      return false;
    }
    if (this._bytes > capB) {
      const mib = Math.round(capB / (1024 * 1024));
      this._reason =
        `Aggregate decompressed-bytes budget exhausted at ${mib} MiB — ` +
        `further nested-archive rows skipped to bound memory.`;
      return false;
    }
    return true;
  }

  get exhausted() { return !!this._reason; }
  get reason()    { return this._reason; }
  get entries()   { return this._entries; }
  get bytes()     { return this._bytes; }
}

// Browser-side global so renderers can read `app._archiveBudget` without an
// ES-module import (Loupe ships as one concatenated `<script>`).
if (typeof window !== 'undefined') window.ArchiveBudget = ArchiveBudget;
