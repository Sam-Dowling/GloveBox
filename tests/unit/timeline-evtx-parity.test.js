'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-evtx-parity.test.js — regression coverage for the
// `_evtxEvents.length === store.rowCount` invariant.
//
// Background: `TimelineView.fromEvtx` (sync EVTX path, used as the
// fallback when the timeline parse worker is unavailable — Firefox on
// `file://`, worker rejected, etc.) used to pass the FULL untruncated
// `events` array into the constructor while building `store` from a
// `list` slice truncated to `TIMELINE_MAX_ROWS`. Consumers in
// `timeline-summary.js:378` and `timeline-detections.js` walk
// `this._evtxEvents[i]` in parallel with `this._timeMs[i]` and
// `this.store.getRow(i)`; on EVTX > TIMELINE_MAX_ROWS the parallel-array
// indices ran past the truncated row count and read undefined timestamps
// + empty rows. The worker path
// (`src/workers/timeline.worker.js::_parseEvtx`) sliced its
// `trimmedEvents` to `list.length` correctly; the sync factory did not.
//
// This test is intentionally a static-source test — the constructor
// pulls in the full `_buildDOM`/`localStorage`/`requestAnimationFrame`
// surface, which would require a heavy fake-DOM harness to exercise
// directly. The two assertions below catch the regression class
// without that harness:
//
//   1. `fromEvtx` must NOT pass a bare `evtxEvents: events` reference
//      where `events` is the untrucated parser output. It must pass
//      the same slice (`list`) that the RowStoreBuilder consumes.
//   2. The constructor must include a runtime invariant check that
//      throws when `_evtxEvents.length !== store.rowCount`. Without
//      this guard a future caller that gets the slice wrong silently
//      reintroduces the same parallel-array desync.
//
// The e2e parity test (`tests/e2e-fixtures/timeline-rowstore-parity.spec.ts`)
// asserts the runtime equality on the worker path.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const TIMELINE_VIEW_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view.js'),
  'utf8',
);
// B2a: the static factories `fromCsvAsync` / `fromEvtx` / `fromSqlite`
// were hoisted into a sibling mixin file. The semantic invariants
// guarded here still hold; only the source location changed.
const TIMELINE_FACTORIES_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-factories.js'),
  'utf8',
);

test('TimelineView constructor enforces _evtxEvents/store row-count invariant', () => {
  // The throw must reference both `evtxEvents.length` and `store.rowCount`
  // and must fire from the constructor (i.e. before any renderer wiring).
  // We pin the exact phrasing because a future refactor that softens the
  // check to a `console.warn` would silently reintroduce the desync.
  const re =
    /this\._evtxEvents && this\._evtxEvents\.length !== this\.store\.rowCount[\s\S]*?throw new Error\([\s\S]*?evtxEvents\.length/;
  assert.match(
    TIMELINE_VIEW_SRC,
    re,
    'TimelineView constructor must throw when evtxEvents.length !== store.rowCount',
  );
});

test('fromEvtx passes the truncated list (not the full events array) as evtxEvents', () => {
  // Locate the body of `static async fromEvtx(...)` and assert that the
  // `evtxEvents:` field of the TimelineView constructor call references
  // the truncated `list` rather than the unbounded `events`. The
  // permitted shapes are:
  //   • `evtxEvents: list` (when fromEvtx aliases events→list directly)
  //   • `evtxEvents: list === events ? events : list` (the current shape,
  //     which avoids a redundant slice when no truncation occurred)
  //   • `evtxEvents: events.slice(0, list.length)` (an alternative shape)
  // The shape that MUST NOT appear is `evtxEvents: events,` — that's
  // the regression we're defending against.
  // Post-B2a: the factory lives in `timeline-view-factories.js` and
  // is attached via `Object.assign(TimelineView, {...})`, so the
  // signature is `async fromEvtx(file, buffer)` (no `static` keyword
  // — implicit when assigned to the constructor).
  const fromEvtxStart = TIMELINE_FACTORIES_SRC.indexOf(
    'async fromEvtx(file, buffer)',
  );
  assert.notEqual(fromEvtxStart, -1, 'fromEvtx factory must exist in timeline-view-factories.js');

  // Find the end of the function — `fromSqlite` follows `fromEvtx`.
  const fromSqliteStart = TIMELINE_FACTORIES_SRC.indexOf(
    'fromSqlite(',
    fromEvtxStart,
  );
  assert.notEqual(fromSqliteStart, -1, 'fromSqlite must follow fromEvtx');
  const fromEvtxBody = TIMELINE_FACTORIES_SRC.slice(fromEvtxStart, fromSqliteStart);

  // The forbidden shape — bare `events,` immediately after `evtxEvents:`.
  // Allow whitespace but nothing else.
  assert.doesNotMatch(
    fromEvtxBody,
    /evtxEvents:\s*events\s*,/,
    'fromEvtx must not pass the full untruncated `events` array as evtxEvents',
  );

  // The required shape — `evtxEvents:` must appear and reference `list`
  // (either directly or via a conditional/slice expression that
  // ultimately yields `list`-length rows).
  assert.match(
    fromEvtxBody,
    /evtxEvents:[^,]*\blist\b/,
    'fromEvtx must reference the truncated `list` when constructing evtxEvents',
  );
});

test('worker EVTX path slices trimmedEvents to list.length (the path the sync factory must mirror)', () => {
  // Sanity check that the worker still performs the slice; if a future
  // refactor removed the slice from the worker we'd want to know about
  // that too, even though it's not what this fix is about.
  const workerSrc = fs.readFileSync(
    path.join(REPO_ROOT, 'src/workers/timeline.worker.js'),
    'utf8',
  );
  // `new Array(list.length)` is the canonical shape; pin it.
  assert.match(
    workerSrc,
    /const\s+trimmedEvents\s*=\s*new\s+Array\(\s*list\.length\s*\)/,
    'timeline.worker.js::_parseEvtx must size trimmedEvents to list.length',
  );
});
