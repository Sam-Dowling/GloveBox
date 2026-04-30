'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-query-editor.js — TimelineQueryEditor class.
//
// Split out of the legacy app-timeline.js monolith. Owns the
// overlay <textarea> + syntax-highlighted <pre> + suggestion dropdown +
// inline history + undo/redo ring. Bound to a TimelineView instance via
// constructor opts.
//
// Loads AFTER timeline-query.js (uses _tlSuggestContext, _tlTokenize,
// _tlParseQuery, _tlFormatHighlightHtml, _tlCompileAst, etc.) and
// BEFORE timeline-view.js (which instantiates it from _buildDOM /
// _wireEvents).
// ════════════════════════════════════════════════════════════════════════════

// ════════════════════════════════════════════════════════════════════════════
// TimelineQueryEditor — overlay `<textarea>` + syntax-highlighted `<pre>`
// + suggestion dropdown. Owned by a TimelineView.
//
// Design note (see CONTRIBUTING / DSL query editor): the suggestion
// popover is driven by a small, explicit state machine, NOT by
// heuristics over every caret position. This replaces the old design
// that reran `_updateSuggestions` on every `input` / `click`, invented
// a `_suppressUntilSpace` guard to stop Enter hijacking after accept,
// and rebuilt every row on every keystroke.
//
//   State:
//     this._sugg = {
//       el,               // the portalled dropdown element, created once
//       items,            // current item list
//       sel,              // selected index
//       ctx,              // _tlSuggestContext() snapshot at last open
//       anchorTokenStart, // ctx.tokenStart when opened
//       itemsKey,         // cheap hash so re-renders reuse rows
//     } | null
//     this._dismissedTokenStart = integer | null   // Esc → set; leaving
//                                                  // the token clears it.
//
//   Open triggers (explicit): user-initiated `input` events (except
//     programmatic setValue), AND Ctrl/Cmd-Space (manual request). No
//     `click` trigger — moving the caret through finished tokens does
//     not spawn a popover.
//
//   Close triggers: Escape (also marks dismissed for this token),
//     focus loss (blur with relatedTarget outside popover), outside
//     pointerdown, window resize, view scroll, programmatic setValue.
//
//   The caret-in-quoted-string guard and token-boundary checks are all
//   absorbed by `_tlSuggestContext` returning `kind: 'none'`; once the
//   context is 'none' the popover just closes. No other "when to open"
//   logic lives in this class.
// ════════════════════════════════════════════════════════════════════════════
class TimelineQueryEditor {
  constructor(opts) {
    this.view = opts.view;
    this.onChange = opts.onChange || (() => { });
    this.onCommit = opts.onCommit || (() => { });
    // `onWindowChange(win)` — called when the inline datetime range
    // widget commits a new {min,max} (or null = "Any time"). The view
    // wires it to mutate `_window` + run `_applyWindowOnly` + schedule
    // a render. Same contract as the legacy `tl-range-banner` Clear
    // button; replaces `_renderRangeBanner` as the only window-state
    // surface visible to the analyst.
    this.onWindowChange = opts.onWindowChange || (() => { });
    // Formatters are injected so the editor stays decoupled from the
    // view's numeric/UTC mode. The view passes `_tlFormatFullUtc`,
    // `_tlFormatDuration`, `_tlFormatNumericTick`, `_tlParseRelative`,
    // and lambdas for `isNumeric` / `dataRange`. All optional — fall
    // back to a no-op formatter so the constructor never throws.
    this.formatters = opts.formatters || {};
    this.debounceMs = opts.debounceMs != null ? opts.debounceMs : 60;
    // Active time window — null means "Any time" (no filter). Mutations
    // come from (a) the datetime widget popover (Apply / Clear / preset
    // chip), (b) the public `setWindow(win)` called by the view when the
    // scrubber / chart-drag mutates `_window`. Render-only — committing
    // a value goes through `onWindowChange`.
    this._window = opts.initialWindow || null;
    // Live drag-preview flag — when true the compact button gets a
    // `--preview` modifier (dashed / pulsing) so the analyst can see
    // they haven't released yet. Set via `setWindow({preview:true})`,
    // cleared on the next non-preview call.
    this._windowPreview = false;
    this._datePopover = null;

    this._debounceTimer = 0;
    this._sugg = null;                   // suggestion state (see class header)
    this._dismissedTokenStart = null;    // Esc → pinned to ctx.tokenStart; cleared on token change
    this._history = TimelineQueryEditor._loadHistory();

    // ── Unified in-memory undo/redo ring ──────────────────────────────────
    // Session-only (deliberately NOT persisted — see CONTRIBUTING). A single
    // ring owns every edit: typing (coalesced VS-Code-style), paste/cut,
    // clause-delete (Ctrl/⌘-Backspace), clear button, Esc-clear, history
    // pick, programmatic `setValue()`. Both `Ctrl/⌘-Z` (undo) and
    // `Ctrl/⌘-Shift-Z` / `Ctrl-Y` (redo) walk this ring exclusively — we
    // always preventDefault on those keys so the native <textarea> undo
    // stack (which can't reach non-typing changes) never runs alongside
    // and desyncs us.
    //
    // Each frame is `{ value, selStart, selEnd }` so undo/redo restore
    // the exact caret position (native-feeling). Coalescing: two
    // consecutive `'type'` snapshots that differ by a single word-char
    // insertion or deletion within `_HIST_COALESCE_MS` are folded into
    // one entry. Any whitespace / operator / quote / paren break starts
    // a new entry, matching VS Code / Sublime / the browser textarea's
    // own behaviour. `'replace'` and `'delete'` snapshots never coalesce.
    this._HIST_MAX = 500;
    this._HIST_COALESCE_MS = 500;
    this._hist = [{ value: '', selStart: 0, selEnd: 0 }];
    this._histIdx = 0;
    this._lastSnapKind = 'replace';
    this._lastSnapTime = 0;
    this._isUndoing = false;


    // Bound doc-level listeners, installed only while a popover is open.
    // Kept as properties so we can remove the exact same references.
    this._onDocPointerDown = (e) => this._handleOutsidePointer(e);
    this._onWinResize = () => this._repositionSuggest();
    this._onViewScroll = (e) => this._handleScroll(e);

    this._buildDom();
    this.setValue(opts.initialValue || '');
  }

  _buildDom() {
    const root = document.createElement('div');
    root.className = 'tl-query';
    // Layout (left → right):
    //   [datetime range] [─── editor (flex) ───] [✕] [▾] [?]
    //
    // The datetime range button replaces the legacy `tl-range-banner`
    // (a separate full-width strip above the editor) — it shows the
    // active `_window` as two stacked timestamps with a delta, opens a
    // popover for absolute / relative input on click, and flips to an
    // "Any time" empty state when no window is set. The clear / history
    // / help cluster moved to the trailing edge so the editor anchors
    // visually between the two control groups.
    root.innerHTML = `
      <div class="tl-query-inner">
        <button class="tl-query-daterange" type="button" tabindex="-1"
                title="Filter by time range — click to set absolute / relative">
          <span class="tl-query-daterange-body"></span>
        </button>
        <div class="tl-query-editor">
          <pre class="tl-query-hl" aria-hidden="true"><code></code></pre>
          <textarea class="tl-query-input" spellcheck="false" autocomplete="off" autocorrect="off" autocapitalize="off" rows="1" placeholder='Filter — e.g. User:admin AND (EventID=4624 OR EventID=4625) NOT "svc_backup"'></textarea>
        </div>
        <button class="tl-query-clear" type="button" title="Clear filter" tabindex="-1">✕</button>
        <button class="tl-query-history" type="button" title="History (Ctrl/⌘-↓)" tabindex="-1">▾</button>
        <button class="tl-query-help" type="button" title="Query language help (Ctrl/⌘-Z undo · Ctrl/⌘-Shift-Z redo · Ctrl/⌘-Backspace delete clause)" tabindex="-1">?</button>
      </div>
      <div class="tl-query-status" aria-live="polite"></div>
    `;
    this.root = root;
    this.input = root.querySelector('.tl-query-input');
    this.hl = root.querySelector('.tl-query-hl code');
    this.status = root.querySelector('.tl-query-status');
    this.clearBtn = root.querySelector('.tl-query-clear');
    this.historyBtn = root.querySelector('.tl-query-history');
    this.helpBtn = root.querySelector('.tl-query-help');
    this.daterangeBtn = root.querySelector('.tl-query-daterange');
    this.daterangeBody = root.querySelector('.tl-query-daterange-body');

    // Input event = user typed / pasted / cut. This is the ONE place we
    // consider opening the popover automatically. `e.isComposing` skips
    // IME pre-edit events (we wait for compositionend). Every `input`
    // also snaps a frame onto the unified undo/redo ring — `_snapshotHistory`
    // coalesces consecutive word-char keystrokes inside the timeout so
    // Ctrl-Z doesn't walk letter-by-letter through a field name, but any
    // whitespace / operator / quote / paren immediately breaks the run
    // (matching VS Code / Sublime / the browser's own textarea).
    this.input.addEventListener('input', (e) => {
      if (e && e.isComposing) return;
      // Any real input invalidates a prior "Escape-dismissed here": the
      // user has moved on. Clear the dismissal if the caret left the
      // pinned token, else leave it so Escape sticks while still typing.
      this._maybeClearDismissal();
      if (!this._isUndoing) {
        // Paste / cut / drop events arrive on the `input` stream with
        // `inputType` flags we can use to classify the edit. Treat any
        // multi-char insertion or non-type inputType as a `replace` so
        // the whole pasted span is one undo step rather than coalescing
        // into a neighbouring word run.
        const it = e && e.inputType;
        const kind = (it === 'insertFromPaste' || it === 'insertFromDrop'
          || it === 'deleteByCut' || it === 'historyUndo' || it === 'historyRedo')
          ? 'replace' : 'type';
        this._snapshotHistory(kind);
      }
      this._refreshHighlight();
      this._scheduleCommit();
      this._refreshSuggest({ allowOpen: true });
    });
    this.input.addEventListener('compositionend', () => {
      // IME commit — one atomic frame for the whole composed run.
      if (!this._isUndoing) this._snapshotHistory('replace');
      this._refreshHighlight();
      this._scheduleCommit();
      this._refreshSuggest({ allowOpen: true });
    });


    this.input.addEventListener('keydown', (e) => this._onKeyDown(e));
    this.input.addEventListener('scroll', () => {
      // Mirror scroll so the highlight layer stays aligned.
      this.hl.parentNode.scrollLeft = this.input.scrollLeft;
      this.hl.parentNode.scrollTop = this.input.scrollTop;
      // And reposition the popover so it stays glued to the caret.
      if (this._sugg) this._repositionSuggest();
    });

    this.input.addEventListener('blur', (e) => {
      // Only close if focus actually left both the input and the popover.
      // The popover rows use `pointerdown.preventDefault()` so focus never
      // moves to them, but we check relatedTarget as a belt-and-braces.
      const next = e.relatedTarget;
      if (this._sugg && this._sugg.el && next && this._sugg.el.contains(next)) return;
      this._closeSuggest();
    });

    // Deliberately NO click handler that *opens* suggestions — clicking
    // between finished tokens should not spawn a popover. If the user
    // wants them, Ctrl/Cmd-Space is the manual trigger. Arrow keys still
    // fire keydown → `_onKeyDown` which intercepts navigation when the
    // popover is open.
    //
    // BUT: if a popover is already open and the user moves the caret to
    // a different token via mouse click or a non-typing key (Home / End /
    // PageUp / PageDown / Arrow* without modifier), the popover's `ctx`
    // is now stale — its `replaceStart`/`replaceEnd` still point at the
    // ORIGINAL anchor token. Pressing Enter at that point would call
    // `_applySuggest(true)` against the stale range and rewrite an
    // unrelated part of the query. Concrete repro: type
    // `user IN (a, b) AND ISP:"x"`, select+Backspace `user IN (a, b) AND `,
    // click at end, press Enter — the editor used to swap `ISP:` for
    // `any:` because the popover from the post-Backspace caret was
    // anchored at tokenStart 0. The handlers below close the popover
    // when the caret leaves its anchor token, mirroring how every other
    // IDE behaves.
    this.input.addEventListener('click', () => this._revalidateSuggestForCaret());
    this.input.addEventListener('keyup', (e) => {
      // Only act on caret-mover keys that DON'T already get handled in
      // _onKeyDown (which `return`s before reaching keyup logic and
      // covers popover-open arrow nav). Modifier-bearing arrows are
      // word-jumps that also count.
      const k = e.key;
      if (k === 'ArrowLeft' || k === 'ArrowRight' || k === 'ArrowUp' || k === 'ArrowDown'
        || k === 'Home' || k === 'End' || k === 'PageUp' || k === 'PageDown') {
        this._revalidateSuggestForCaret();
      }
    });

    this.clearBtn.addEventListener('click', () => {
      if (this.input.value === '') return;
      this.setValue('');
      this._scheduleCommit(true);
      this._closeSuggest();
      this.input.focus();
    });
    this.historyBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      this._openHistoryMenu();
    });
    this.helpBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      this._openHelpPopover();
    });
    this.daterangeBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      this._toggleDatePopover();
    });
    // Initial paint — empty state (or active window if `initialWindow`
    // was supplied). Keeps the button visually populated before the
    // view has had a chance to push a window via `setWindow`.
    this._renderDaterangeButton();
  }

  // Public API — setValue is used on history-pick, query restore, and
  // clear. It's a programmatic change, so it MUST NOT auto-open the
  // popover (rule: open-on-user-input only).
  //
  // Every value mutation goes onto the unified undo/redo ring as a
  // non-coalescing `'replace'` frame so Ctrl/⌘-Z can roll it back in one
  // hop (matching VS Code / Sublime behaviour on paste or macro edits).
  // The `_isUndoing` guard prevents a frame-apply during undo from
  // re-snapshotting the value it just restored.
  setValue(v) {
    const next = v || '';
    const prev = this.input.value;
    this.input.value = next;
    this._refreshHighlight();
    this._closeSuggest();
    this._dismissedTokenStart = null;
    if (!this._isUndoing && prev !== next) this._snapshotHistory('replace');
  }
  getValue() { return this.input.value; }

  focus() { this.input.focus(); }

  setStatus(html, kind) {
    this.status.className = 'tl-query-status' + (kind ? ' tl-query-status-' + kind : '');
    this.status.innerHTML = html || '';
  }

  _refreshHighlight() {
    const raw = this.input.value || '';
    const tokens = _tlTokenize(raw);
    this.hl.innerHTML = _tlFormatHighlightHtml(tokens);
  }

  _scheduleCommit(immediate) {
    clearTimeout(this._debounceTimer);
    const run = () => {
      this._debounceTimer = 0;
      try { this.onChange(this.input.value); } catch (e) { /* noop */ }
    };
    if (immediate) run(); else this._debounceTimer = setTimeout(run, this.debounceMs);
  }

  // ── Unified undo/redo ring ───────────────────────────────────────────
  // Push the current `{value, selStart, selEnd}` onto `_hist`. `kind`
  // classifies the edit for the coalescing heuristic:
  //   'type'    — ordinary keystroke from the `input` stream. Coalesces
  //               with the previous 'type' frame iff (a) the prior frame
  //               was 'type' within `_HIST_COALESCE_MS`, AND (b) the
  //               diff between prev.value and current.value is a single
  //               word-char insertion or deletion at the caret. Any
  //               whitespace / operator / quote / paren break starts a
  //               new entry — matches VS Code, Sublime, and the browser's
  //               native textarea. A selection-replacement (non-empty
  //               selStart != selEnd collapsed to a single-char diff) is
  //               treated as a fresh frame regardless.
  //   'replace' — paste / drop / cut / compositionend / programmatic
  //               `setValue()` / history-pick / clear. Never coalesces.
  //   'delete'  — Ctrl/⌘-Backspace clause-delete output. Never coalesces.
  //
  // Truncates any pending redo tail on a new edit (standard undo-ring
  // semantics — typing after undo discards the redo path), and caps the
  // ring at `_HIST_MAX` to bound memory. The first frame is the empty
  // value pushed at construction time, so `_histIdx === 0` always holds
  // a valid snapshot to undo back to.
  _snapshotHistory(kind) {
    const value = this.input.value;
    const selStart = this.input.selectionStart || 0;
    const selEnd = this.input.selectionEnd || selStart;
    const now = Date.now();
    const head = this._hist[this._histIdx];
    // No-op: value and selection unchanged.
    if (head && head.value === value && head.selStart === selStart && head.selEnd === selEnd) {
      this._lastSnapKind = kind;
      this._lastSnapTime = now;
      return;
    }
    // Coalesce consecutive typing runs when the diff is a single word-char
    // edit at the caret. Whitespace / operator / quote / paren breaks the
    // run and forces a new frame — matches VS Code word-boundary undo.
    if (kind === 'type' && this._lastSnapKind === 'type'
      && head && head.value !== value
      && (now - this._lastSnapTime) < this._HIST_COALESCE_MS
      && this._isSimpleWordCharEdit(head.value, value)) {
      // Replace the head frame in-place (don't push a new one).
      this._hist[this._histIdx] = { value, selStart, selEnd };
      this._lastSnapKind = 'type';
      this._lastSnapTime = now;
      return;
    }
    // Truncate redo tail on any new edit.
    if (this._histIdx < this._hist.length - 1) {
      this._hist.length = this._histIdx + 1;
    }
    this._hist.push({ value, selStart, selEnd });
    this._histIdx = this._hist.length - 1;
    // Cap ring length.
    if (this._hist.length > this._HIST_MAX) {
      const drop = this._hist.length - this._HIST_MAX;
      this._hist.splice(0, drop);
      this._histIdx -= drop;
      if (this._histIdx < 0) this._histIdx = 0;
    }
    this._lastSnapKind = kind;
    this._lastSnapTime = now;
  }

  // Returns true iff `next` is exactly `prev` with a single word-char
  // inserted or deleted anywhere. Word-char = `[A-Za-z0-9_]`. Any diff
  // involving whitespace / operator / quote / paren / bracket returns
  // false so those characters force a new undo frame (VS-Code parity).
  _isSimpleWordCharEdit(prev, next) {
    const dLen = next.length - prev.length;
    if (dLen !== 1 && dLen !== -1) return false;
    const shorter = dLen === 1 ? prev : next;
    const longer = dLen === 1 ? next : prev;
    // Find first diverging char.
    let i = 0;
    const n = shorter.length;
    while (i < n && shorter.charCodeAt(i) === longer.charCodeAt(i)) i++;
    // Remaining suffix must match.
    const suffixLenShorter = n - i;
    if (longer.slice(longer.length - suffixLenShorter) !== shorter.slice(i)) return false;
    const ch = longer.charAt(i);
    return /[A-Za-z0-9_]/.test(ch);
  }

  // Step back one frame. Suppresses `_snapshotHistory` during apply via
  // `_isUndoing` so the input-event flush (from the programmatic value
  // change) doesn't re-push the frame we just restored.
  _undo() {
    if (this._histIdx <= 0) return;
    this._histIdx--;
    this._applyHistFrame(this._hist[this._histIdx]);
  }

  // Step forward one frame (if a redo tail exists).
  _redo() {
    if (this._histIdx >= this._hist.length - 1) return;
    this._histIdx++;
    this._applyHistFrame(this._hist[this._histIdx]);
  }

  _applyHistFrame(f) {
    if (!f) return;
    this._isUndoing = true;
    try {
      this.input.value = f.value;
      const s = Math.max(0, Math.min(f.value.length, f.selStart));
      const e = Math.max(0, Math.min(f.value.length, f.selEnd));
      this.input.setSelectionRange(s, e);
      this._refreshHighlight();
      this._scheduleCommit();
      this._closeSuggest();
      this._dismissedTokenStart = null;
    } finally {
      this._isUndoing = false;
    }
    // Break coalescing — next keystroke starts a fresh run regardless of
    // what kind the restored frame was tagged as.
    this._lastSnapKind = 'replace';
    this._lastSnapTime = 0;
  }

  // ── Clause-aware delete (Ctrl/⌘-Backspace, Ctrl/⌘-Delete) ────────────
  // Walks the DSL token stream from `_tlTokenize` so that a single
  // chord deletes a whole DSL clause rather than one word at a time.
  // `dir` is `'back'` (Ctrl-Backspace) or `'forward'` (Ctrl-Delete).
  //
  // Semantics (back):
  //   caret after VALUE preceded by `WORD OP VALUE`      → delete WORD + OP + VALUE
  //   caret after OP in `WORD OP` (no value yet)         → delete WORD + OP
  //   caret after bare WORD / NUMBER / KW                → delete that token
  //   caret after `(` / `)` / STRING / REGEX             → delete that token
  //   caret inside an unterminated STRING / REGEX        → fall through to native
  //   caret at a selection                               → fall through to native
  // After any deletion, leading/trailing whitespace around the cut span
  // is collapsed so clauses don't leave `  ` runs behind.
  //
  // Forward direction is the mirror image.
  //
  // Returns true iff we handled the key; caller calls preventDefault in
  // that case. Returning false lets the textarea run its native handler.
  _deleteClause(dir) {
    const input = this.input;
    const selS = input.selectionStart || 0;
    const selE = input.selectionEnd || selS;
    if (selS !== selE) return false;    // non-empty selection → native delete
    const text = input.value;
    if (!text) return false;
    // Don't DSL-walk into an unterminated string/regex — native behaviour
    // is more predictable there.
    const toks = _tlTokenize(text);
    // Find the token index whose range brackets the caret. For a caret
    // sitting exactly on a token boundary, `back` looks at the token
    // ending there; `forward` looks at the token starting there.
    const caret = selS;
    // Bail if caret is inside a STRING / REGEX / ERR with no close.
    for (let i = 0; i < toks.length; i++) {
      const t = toks[i];
      if (caret > t.start && caret < t.end
        && (t.kind === 'STRING' || t.kind === 'REGEX' || t.kind === 'ERR')) {
        return false;
      }
    }

    if (dir === 'back') {
      // Find the last non-WS token ending at or before the caret.
      let ix = -1;
      for (let i = toks.length - 1; i >= 0; i--) {
        const t = toks[i];
        if (t.end <= caret && t.kind !== 'WS') { ix = i; break; }
      }
      if (ix < 0) return false;
      let startIx = ix, endIx = ix;
      const t = toks[ix];
      // Three-token pattern: WORD OP VALUE (where VALUE is our current tok).
      if (t.kind === 'WORD' || t.kind === 'STRING' || t.kind === 'NUMBER' || t.kind === 'REGEX') {
        // Look back through WS.
        let j = ix - 1;
        while (j >= 0 && toks[j].kind === 'WS') j--;
        if (j >= 0 && toks[j].kind === 'OP' && toks[j].text !== ',') {
          let k = j - 1;
          while (k >= 0 && toks[k].kind === 'WS') k--;
          if (k >= 0 && (toks[k].kind === 'WORD' || toks[k].kind === 'STRING')) {
            startIx = k;
          } else {
            startIx = j;   // OP without a field → delete OP + VALUE
          }
        }
      } else if (t.kind === 'OP' && t.text !== ',') {
        // Two-token pattern: WORD OP (no value yet).
        let j = ix - 1;
        while (j >= 0 && toks[j].kind === 'WS') j--;
        if (j >= 0 && (toks[j].kind === 'WORD' || toks[j].kind === 'STRING')) startIx = j;
      }
      // Compute splice range + collapse one run of leading whitespace
      // immediately before startIx so we don't leave "a  b" after deleting
      // the clause in between.
      let delStart = toks[startIx].start;
      const delEnd = toks[endIx].end;
      // Swallow one WS run before delStart.
      let ws = delStart;
      while (ws > 0 && (text.charAt(ws - 1) === ' ' || text.charAt(ws - 1) === '\t')) ws--;
      // But keep at least one space if both sides have non-WS content,
      // so `foo AND bar` → Ctrl-Backspace → `foo ` (not `foo`) when the
      // caret was at the end of `bar`. Simple rule: if there's no content
      // after delEnd (trailing clause), collapse all; otherwise keep one.
      const tailIsEmpty = text.slice(delEnd).replace(/\s+$/, '') === '';
      if (!tailIsEmpty && ws < delStart) ws = Math.max(ws, delStart - 0);
      delStart = tailIsEmpty ? ws : delStart;
      return this._applyEdit(delStart, delEnd, '', delStart);
    }

    // Forward: mirror image.
    let ix = -1;
    for (let i = 0; i < toks.length; i++) {
      const t = toks[i];
      if (t.start >= caret && t.kind !== 'WS') { ix = i; break; }
    }
    if (ix < 0) return false;
    let startIx = ix, endIx = ix;
    const t = toks[ix];
    if (t.kind === 'WORD' || t.kind === 'STRING') {
      // WORD OP VALUE pattern, forwards.
      let j = ix + 1;
      while (j < toks.length && toks[j].kind === 'WS') j++;
      if (j < toks.length && toks[j].kind === 'OP' && toks[j].text !== ',') {
        let k = j + 1;
        while (k < toks.length && toks[k].kind === 'WS') k++;
        if (k < toks.length && (toks[k].kind === 'WORD' || toks[k].kind === 'STRING'
          || toks[k].kind === 'NUMBER' || toks[k].kind === 'REGEX')) {
          endIx = k;
        } else {
          endIx = j;
        }
      }
    }
    let delStart = toks[startIx].start;
    let delEnd = toks[endIx].end;
    // Swallow one WS run after delEnd so `a  b` → `a` when deleting `b`.
    const headIsEmpty = text.slice(0, delStart).replace(/^\s+/, '') === '';
    if (headIsEmpty) {
      while (delEnd < text.length && (text.charAt(delEnd) === ' ' || text.charAt(delEnd) === '\t')) delEnd++;
    }
    return this._applyEdit(delStart, delEnd, '', delStart);
  }

  // Splice `[start, end)` in the textarea with `replacement`, set caret
  // to `caret`, refresh highlight, snapshot the result onto the history
  // ring as a `'delete'` frame (never coalesces), and schedule a commit.
  // Returns true so callers can tail-call this and preventDefault in
  // one step.
  _applyEdit(start, end, replacement, caret) {
    const before = this.input.value;
    const next = before.slice(0, start) + (replacement || '') + before.slice(end);
    if (next === before) return true;
    this.input.value = next;
    const c = Math.max(0, Math.min(next.length, caret == null ? start : caret));
    this.input.setSelectionRange(c, c);
    this._refreshHighlight();
    // Snapshot as `'delete'` so it never coalesces with surrounding typing.
    this._snapshotHistory('delete');
    this._scheduleCommit();
    this._closeSuggest();
    this._dismissedTokenStart = null;
    return true;
  }

  _onKeyDown(e) {
    // Ctrl/⌘-Z — undo via the unified ring (session-only). We ALWAYS
    // preventDefault here so the textarea's native undo stack (which
    // can't see non-typing changes like the clear button or history
    // pick) never runs alongside and desyncs us. Ctrl/⌘-Shift-Z and
    // Ctrl-Y redo. The actual apply sets `_isUndoing` so the resulting
    // `input` event doesn't re-snapshot the frame we just restored.
    const isUndoKey = (e.key === 'z' || e.key === 'Z')
      && (e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey;
    const isRedoKey = ((e.key === 'z' || e.key === 'Z') && (e.ctrlKey || e.metaKey) && e.shiftKey && !e.altKey)
      || ((e.key === 'y' || e.key === 'Y') && (e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey);
    if (isRedoKey) { e.preventDefault(); this._redo(); return; }
    if (isUndoKey) { e.preventDefault(); this._undo(); return; }

    // Ctrl/⌘-Backspace — delete the entire DSL clause to the left of
    // the caret (comparison operand, single token, or whole
    // `field op value` triple). Falls through to native word-delete on
    // unterminated strings/regex or when the tokenizer can't find a
    // clause boundary, so analysts never lose the familiar shortcut.
    // Symmetric Ctrl/⌘-Delete for the forward direction.
    if (e.key === 'Backspace' && (e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey) {
      if (this._deleteClause('back')) { e.preventDefault(); return; }
      // else fall through to native Ctrl-Backspace
    }
    if (e.key === 'Delete' && (e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey) {
      if (this._deleteClause('forward')) { e.preventDefault(); return; }
    }
    // Manual trigger — Ctrl/Cmd-Space forces suggestions to recompute + open,
    // overriding any prior Esc dismissal for the current token. Mirrors
    // VS Code, Chrome DevTools, most IDEs.
    if (e.key === ' ' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      this._dismissedTokenStart = null;
      this._refreshSuggest({ allowOpen: true, force: true });
      return;
    }

    // Ctrl/Cmd+↓ toggles the history menu without leaving the keyboard.
    // Alt+↓ is accepted as a fallback (matches older builds / docs), but
    // Ctrl/⌘ is the canonical binding — it's what combo-boxes on every
    // major platform use and doesn't collide with WM window shortcuts.
    if (e.key === 'ArrowDown' && (e.ctrlKey || e.metaKey || e.altKey) && !this._isSuggestOpen()) {
      e.preventDefault();
      if (this._isHistoryOpen()) this._closeHistoryMenu();
      else this._openHistoryMenu();
      return;
    }

    // History menu open → arrow keys move selection, Enter/Tab applies,
    // Escape dismisses. Focus stays on the <textarea> the whole time so
    // the user never loses their caret.
    if (this._isHistoryOpen()) {
      if (e.key === 'ArrowDown') { e.preventDefault(); this._moveHistorySel(1); return; }
      if (e.key === 'ArrowUp') { e.preventDefault(); this._moveHistorySel(-1); return; }
      if (e.key === 'Home') { e.preventDefault(); this._setHistorySel(0); return; }
      if (e.key === 'End') { e.preventDefault(); this._setHistorySel(this._history.length - 1); return; }
      if (e.key === 'Enter' || e.key === 'Tab') { e.preventDefault(); this._applyHistorySel(); return; }
      if (e.key === 'Escape') { e.preventDefault(); this._closeHistoryMenu(); return; }
      // Any printable key closes the menu and falls through to the input
      // — matches how <select> behaves when you start typing.
      if (e.key.length === 1) { this._closeHistoryMenu(); /* fall through */ }
    }

    if (this._isSuggestOpen()) {
      if (e.key === 'ArrowDown') { e.preventDefault(); this._moveSuggest(1); return; }
      if (e.key === 'ArrowUp') { e.preventDefault(); this._moveSuggest(-1); return; }
      // Tab / Enter accept the highlighted suggestion ONLY when the
      // popover is actually visible. If state says open but the DOM
      // element isn't visible (zero size / display:none / detached),
      // close the stale state and fall through to the popover-closed
      // Enter / native-Tab handlers below — what the user SEES wins
      // over what the state machine remembers. Reproducible repro:
      // build ` Severity:INFO` by deletion, place caret after the
      // leading space, press Backspace then Enter; without this gate,
      // the editor used to rewrite to `any::INFO` against an
      // invisible popover.
      if (e.key === 'Tab') {
        if (this._isSuggestVisible()) { e.preventDefault(); this._applySuggest(false); return; }
        this._closeSuggest();
        // Fall through: native Tab leaves the textarea.
      } else if (e.key === 'Enter') {
        if (this._isSuggestVisible()) { e.preventDefault(); this._applySuggest(true); return; }
        this._closeSuggest();
        // Fall through to the popover-closed Enter branch below.
      } else if (e.key === 'Escape') {
        e.preventDefault();
        // Pin dismissal to the current token so the popover stays shut
        // while the user keeps typing the same token. Any character that
        // changes the token's start (crossing a boundary) clears it.
        const ctx = this._sugg.ctx;
        this._dismissedTokenStart = ctx ? ctx.tokenStart : null;
        this._closeSuggest();
        return;
      } else {
        // Any other key falls through — the ensuing `input` event will
        // update the item list in-place (no re-creation of the dropdown).
        return;
      }
      // If we reach here, Tab/Enter triggered the visibility fall-through:
      // the popover was just closed, drop into the popover-closed branches
      // below so Enter still submits and Tab still does its native action.
    }

    // Popover closed — Enter / Escape are the committed meanings.
    if (e.key === 'Enter') {
      e.preventDefault();
      this._scheduleCommit(true);
      this._pushHistory(this.input.value);
      try { this.onCommit(this.input.value); } catch (_) { /* noop */ }
      return;
    }
    if (e.key === 'Escape') {
      if (this.input.value !== '') {
        e.preventDefault();
        this.setValue('');
        this._scheduleCommit(true);
      }
      return;
    }
    // Keep single-line.
    if (e.key === 'Enter' || e.key === 'NumpadEnter') e.preventDefault();
  }

  _isSuggestOpen() { return !!(this._sugg && this._sugg.items && this._sugg.items.length); }

  // Stricter than `_isSuggestOpen`: the popover element must also be
  // attached to the DOM and have a real layout box (non-zero size, not
  // `display:none` / `visibility:hidden`). Used to gate Tab/Enter accept
  // gestures so they only fire when the user can actually SEE the
  // popover. Without this, state and DOM could drift apart (e.g. via a
  // late scroll/layout reflow that visually removes the dropdown while
  // `this._sugg` is still set), and Enter would silently rewrite the
  // query against an invisible suggestion list.
  _isSuggestVisible() {
    if (!this._isSuggestOpen()) return false;
    const el = this._sugg.el;
    if (!el || !el.parentNode) return false;
    const rect = el.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return false;
    const view = el.ownerDocument && el.ownerDocument.defaultView;
    if (view) {
      const cs = view.getComputedStyle(el);
      if (cs && (cs.display === 'none' || cs.visibility === 'hidden')) return false;
    }
    return true;
  }

  // Called from `click` / non-typing `keyup` listeners. If a popover is
  // open and the caret has moved to a different token (or out of any
  // completable context), close it so a stale `_sugg.ctx` can't be
  // applied by Enter/Tab. No-op when the caret is still inside the
  // popover's anchor token — the user is still composing the same
  // field/value and the popover legitimately stays open. Also clears
  // any pinned Esc-dismissal once the caret leaves the dismissed token,
  // matching the behaviour the `input` path already had via
  // `_maybeClearDismissal`.
  _revalidateSuggestForCaret() {
    this._maybeClearDismissal();
    if (!this._sugg) return;
    const caret = this.input.selectionStart || 0;
    const ctx = _tlSuggestContext(this.input.value || '', caret);
    const willClose = (ctx.kind === 'none' || ctx.tokenStart !== this._sugg.anchorTokenStart);
    if (willClose) {
      this._closeSuggest();
    }
  }

  // Clear the Esc-dismissal flag iff the caret has left the pinned token.
  _maybeClearDismissal() {
    if (this._dismissedTokenStart == null) return;
    const caret = this.input.selectionStart || 0;
    const ctx = _tlSuggestContext(this.input.value, caret);
    if (ctx.tokenStart !== this._dismissedTokenStart) {
      this._dismissedTokenStart = null;
    }
  }

  // ── Suggestions ────────────────────────────────────────────────────────
  // Single entry point. `allowOpen` says whether this call is eligible to
  // bring up a popover that's currently closed (true for input / manual
  // trigger, false for programmatic refresh). `force` ignores the
  // dismissal flag (manual trigger only).
  _refreshSuggest(opts) {
    const allowOpen = !!(opts && opts.allowOpen);
    const force = !!(opts && opts.force);

    const caret = this.input.selectionStart || 0;
    const text = this.input.value || '';
    const ctx = _tlSuggestContext(text, caret);

    if (ctx.kind === 'none') {
      this._closeSuggest();
      return;
    }

    // Respect a live Esc dismissal pinned to the current token (unless
    // the manual trigger forced through).
    if (!force
      && this._dismissedTokenStart != null
      && this._dismissedTokenStart === ctx.tokenStart) {
      this._closeSuggest();
      return;
    }

    const items = this._itemsFor(ctx);
    if (!items.length) {
      this._closeSuggest();
      return;
    }

    if (this._isSuggestOpen()) {
      // Crossing a token boundary (Backspace consuming a delimiter, or
      // typing space/operator that starts a new token) means the prior
      // popover anchor is stale. Close + reopen so `_sugg.anchorTokenStart`
      // and `_sugg.ctx.tokenStart` stay in lock-step — keeps the
      // accept-time replaceStart/replaceEnd authoritative for the token
      // the user is currently editing.
      if (this._sugg.anchorTokenStart !== ctx.tokenStart) {
        this._closeSuggest();
        if (allowOpen) this._openSuggest(items, ctx);
        return;
      }
      this._updateSuggestItems(items, ctx);
      this._repositionSuggest();
      return;
    }
    if (!allowOpen) {
      return;
    }
    this._openSuggest(items, ctx);
  }

  _itemsFor(ctx) {
    if (ctx.kind === 'field') return this._fieldSuggestions(ctx.prefix);
    if (ctx.kind === 'value') return this._valueSuggestions(ctx.fieldName, ctx.prefix);
    if (ctx.kind === 'keyword') return this._keywordSuggestions(ctx.prefix);
    return [];
  }

  _fieldSuggestions(prefix) {
    const lc = String(prefix || '').toLowerCase();
    const cols = this.view.columns;
    const out = [];
    if ('any'.startsWith(lc) || !lc) out.push({ label: 'any', text: 'any:', kind: 'field' });
    if ('is'.startsWith(lc) || !lc) out.push({ label: 'is', text: 'is:', kind: 'field' });
    for (let i = 0; i < cols.length; i++) {
      const name = String(cols[i] || ''); if (!name) continue;
      const lcName = name.toLowerCase();
      if (!lc || lcName.includes(lc)) {
        const safe = /[\s=!:~<>()"]/.test(name) ? `[${name}]` : name;
        out.push({ label: name, text: safe + ':', kind: 'field', rank: lcName.startsWith(lc) ? 0 : 1 });
      }
    }
    for (const kw of ['AND', 'OR', 'NOT']) {
      if (kw.toLowerCase().startsWith(lc) && lc) out.push({ label: kw, text: kw + ' ', kind: 'kw' });
    }
    out.sort((a, b) => (a.rank || 0) - (b.rank || 0));
    return out.slice(0, 40);
  }

  _valueSuggestions(fieldName, prefix) {
    const lcPrefix = String(prefix || '').toLowerCase();
    const cols = this.view.columns;
    const cleanField = String(fieldName || '').trim();
    if (cleanField.toLowerCase() === 'is') {
      const out = [];
      for (const f of ['sus', 'detection']) {
        if (!lcPrefix || f.startsWith(lcPrefix)) out.push({ label: f, text: f, kind: 'value' });
      }
      return out;
    }
    if (!cleanField || cleanField.toLowerCase() === 'any' || cleanField === '*') return [];
    const lcField = cleanField.toLowerCase();
    let colIdx = -1;
    for (let i = 0; i < cols.length; i++) {
      if (String(cols[i] || '').toLowerCase() === lcField) { colIdx = i; break; }
    }
    if (colIdx < 0) return [];
    const distinct = this.view._distinctValuesFor(colIdx, this.view._filteredIdx || null, 80);
    const out = [];
    for (const [val, count] of distinct) {
      const vs = String(val || '');
      if (lcPrefix && !vs.toLowerCase().includes(lcPrefix)) continue;
      const needsQuote = /[\s=!:~<>()"]/.test(vs) || vs === '';
      // Escape `\` first, then `"` — symmetric with the parser's
      // `replace(/\\\\/g, '\\').replace(/\\"/g, '"')` and matches the
      // canonical encoder in timeline-query.js:632. Without the
      // backslash pass, a value like `a\"` would emit `"a\\""` and
      // mis-parse. Closes CodeQL alert js/incomplete-sanitization.
      const text = needsQuote
        ? `"${vs.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
        : vs;
      out.push({ label: vs === '' ? '(empty)' : vs, text, kind: 'value', count });
    }
    return out.slice(0, 30);
  }

  _keywordSuggestions(prefix) {
    const lc = String(prefix || '').toLowerCase();
    const out = [];
    for (const kw of ['AND', 'OR', 'NOT']) {
      if (!lc || kw.toLowerCase().startsWith(lc)) out.push({ label: kw, text: kw + ' ', kind: 'kw' });
    }
    return out;
  }

  // Cheap stable hash of items (label+kind) so `_updateSuggestItems` can
  // skip DOM rebuilds when only the active index changed.
  _itemsKey(items) {
    let s = '';
    for (const it of items) s += it.kind + '\0' + it.label + '\x1f';
    return s;
  }

  _openSuggest(items, ctx) {
    const el = document.createElement('div');
    el.className = 'tl-query-suggest';
    el.setAttribute('role', 'listbox');
    document.body.appendChild(el);
    this._sugg = { el, items: [], sel: 0, ctx, anchorTokenStart: ctx.tokenStart, itemsKey: '' };
    this._updateSuggestItems(items, ctx);
    this._repositionSuggest();
    document.addEventListener('pointerdown', this._onDocPointerDown, true);
    window.addEventListener('resize', this._onWinResize, true);
    window.addEventListener('scroll', this._onViewScroll, true);
  }

  _updateSuggestItems(items, ctx) {
    if (!this._sugg) return;
    this._sugg.ctx = ctx;
    const key = this._itemsKey(items);
    if (key === this._sugg.itemsKey) return;   // same items, skip rebuild
    this._sugg.itemsKey = key;
    this._sugg.items = items;
    // Clamp selection rather than resetting to 0 — keeps the user's
    // arrow-key position stable while they continue typing.
    if (this._sugg.sel >= items.length) this._sugg.sel = 0;
    const el = this._sugg.el;
    el.innerHTML = '';
    for (let i = 0; i < items.length; i++) {
      const it = items[i];
      const row = document.createElement('div');
      row.className = 'tl-query-suggest-item tl-query-suggest-' + it.kind
        + (i === this._sugg.sel ? ' tl-query-suggest-active' : '');
      row.setAttribute('role', 'option');
      row.dataset.idx = String(i);
      const countHtml = it.count != null
        ? `<span class="tl-query-suggest-count">${it.count.toLocaleString()}</span>` : '';
      row.innerHTML = `<span class="tl-query-suggest-label">${_tlEsc(it.label)}</span>${countHtml}`;
      // pointerdown.preventDefault — keep focus on the textarea so blur
      // doesn't fire mid-accept.
      row.addEventListener('pointerdown', (e) => {
        e.preventDefault();
        this._sugg.sel = i;
        this._applySuggest();
      });
      el.appendChild(row);
    }
  }

  // Pixel-accurate caret positioning via a hidden mirror span in the
  // existing highlight `<pre><code>` layer. The layer already occupies
  // the exact same padding-box as the textarea (see core CSS comment on
  // `.tl-query-hl, .tl-query-input`), so a `<span>` stuffed with the
  // text-up-to-caret has its bounding rect exactly where the caret is.
  // Survives zoom, font changes, proportional-looking monospace fonts,
  // horizontal scroll of the textarea.
  _caretScreenPos() {
    const caret = this.input.selectionStart || 0;
    const text = this.input.value.slice(0, caret) || '';
    // Build a mirror string: NBSP for leading spaces so the span actually
    // renders them. The highlight layer uses `white-space: pre`, so we
    // can put raw text including spaces.
    const probe = document.createElement('span');
    // Empty/short string is fine — `probeWidth === 0` is meaningful
    // (caret at column 0). We don't need a zero-width anchor anymore;
    // the textarea's own padding-box origin is the column-0 X.
    probe.textContent = text;
    // Park inside the code element, preserving its current children so
    // we can restore on teardown. We don't actually want the probe to
    // be visible — the user is looking at the tokenised highlight, not
    // the raw text. Use `visibility: hidden` + `position: absolute` so
    // it occupies space for layout measurement without painting.
    probe.style.cssText = 'visibility:hidden;position:absolute;left:-99999px;top:-99999px;white-space:pre;font:inherit;padding:0;border:0;';
    const hlParent = this.hl.parentNode;   // the <pre>
    hlParent.appendChild(probe);
    // Copy the mirror's computed font metrics from the textarea so the
    // measured width matches the caret column 1:1.
    const cs = getComputedStyle(this.input);
    probe.style.font = cs.font;
    probe.style.letterSpacing = cs.letterSpacing;
    const probeWidth = probe.getBoundingClientRect().width;
    hlParent.removeChild(probe);
    // The caret's client X is the textarea's content-box left (inside
    // padding) + the measured width − scrollLeft. Use the input's rect
    // since its layout box is the authoritative one.
    const inRect = this.input.getBoundingClientRect();
    const padL = parseFloat(cs.paddingLeft) || 0;
    const x = inRect.left + padL + probeWidth - (this.input.scrollLeft || 0);
    const y = inRect.bottom;
    // `probeWidth === 0` is the CORRECT measurement when the caret sits
    // at column 0 with no text before it — NOT a failure mode. The
    // previous guard misfired in that case and returned `anchorRect`,
    // which is the rect of a zero-width <span> inside the off-screen
    // probe (parked at left:-99999), placing the popover ~100,000px
    // off-screen — visually invisible to the user but still passing
    // the size/CSS visibility gate, so Enter would accept and the
    // editor would prepend `any:` to the user's in-progress query.
    // Fall back only when `x` is non-finite (display:none ancestor →
    // all rects collapse to NaN), and use the textarea's own
    // padding-box origin as the fallback. `anchorRect` is never
    // reliable as a fallback because the probe is off-screen by design.
    if (!Number.isFinite(x)) {
      return { x: inRect.left + padL, y: inRect.bottom, inputRect: inRect };
    }
    return { x, y, inputRect: inRect };
  }

  _repositionSuggest() {
    if (!this._sugg) return;
    const el = this._sugg.el;
    const { x, y, inputRect } = this._caretScreenPos();
    // Keep the popover visually inside the viewport with a small margin.
    const margin = 6;
    el.style.position = 'fixed';
    el.style.visibility = 'hidden';      // measure first, then place
    el.style.left = '0px';
    el.style.top = '0px';
    el.style.zIndex = '10001';
    el.style.display = 'block';
    // Force layout read.
    const w = el.offsetWidth || 240;
    const h = el.offsetHeight || 200;
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    // Default: below the caret.
    let left = Math.max(margin, Math.min(vw - w - margin, x - 8));
    let top = y + 2;
    // Flip above if not enough room below and there's room above.
    if (top + h > vh - margin && inputRect.top - h - 2 > margin) {
      top = inputRect.top - h - 2;
    }
    // Defensive symmetric clamp on `top` — mirrors the `left` clamp
    // above. If `_caretScreenPos` ever returns an off-screen Y (regression
    // safety: an earlier bug parked the popover at y≈-99999 because the
    // caret-pos fallback returned the off-screen probe's anchor rect),
    // the clamp keeps the popover visible. Cheap belt-and-braces; the
    // proper fix lives in `_caretScreenPos` itself.
    top = Math.max(margin, Math.min(vh - h - margin, top));
    el.style.left = left + 'px';
    el.style.top = top + 'px';
    el.style.visibility = '';
  }

  _moveSuggest(d) {
    if (!this._sugg) return;
    const items = this._sugg.items;
    if (!items.length) return;
    const prev = this._sugg.sel;
    const next = (prev + d + items.length) % items.length;
    this._sugg.sel = next;
    const rows = this._sugg.el.querySelectorAll('.tl-query-suggest-item');
    if (rows[prev]) rows[prev].classList.remove('tl-query-suggest-active');
    if (rows[next]) {
      rows[next].classList.add('tl-query-suggest-active');
      rows[next].scrollIntoView({ block: 'nearest' });
    }
  }

  _applySuggest(commit) {
    if (!this._sugg) return;
    const item = this._sugg.items[this._sugg.sel];
    if (!item) { this._closeSuggest(); return; }
    const ctx = this._sugg.ctx;
    const before = this.input.value.slice(0, ctx.replaceStart);
    const after = this.input.value.slice(ctx.replaceEnd);
    const inserted = item.text;
    this.input.value = before + inserted + after;
    const newCaret = (before + inserted).length;
    this.input.setSelectionRange(newCaret, newCaret);
    this._refreshHighlight();

    // Accepting a FIELD (inserts "Name:") → caret is now in value context;
    // we want to immediately show value suggestions so the analyst keeps
    // flowing. Accepting a VALUE / KW / IS-flag → natural stop point;
    // close and pin an Escape-equivalent dismissal to this token so the
    // popover doesn't immediately pop back up. Typing whitespace after
    // the accept will cross the token boundary and clear the pin.
    if (item.kind === 'field') {
      // Still composing (need a value next) — debounced commit, no history.
      this._scheduleCommit();
      this._dismissedTokenStart = null;
      this._refreshSuggest({ allowOpen: true, force: true });
    } else {
      // Natural stop point — if triggered by Enter, treat as a full commit
      // so the query is saved to history immediately (the user expects
      // Enter-accept to behave like Enter-submit). Tab keeps the old
      // debounced behaviour so the analyst can keep composing.
      this._scheduleCommit(!!commit);
      const nextCtx = _tlSuggestContext(this.input.value, newCaret);
      this._dismissedTokenStart = nextCtx.tokenStart;
      this._closeSuggest();
      if (commit) {
        this._pushHistory(this.input.value);
        try { this.onCommit(this.input.value); } catch (_) { /* noop */ }
      }
    }
  }

  _closeSuggest() {
    if (!this._sugg) return;
    if (this._sugg.el && this._sugg.el.parentNode) {
      this._sugg.el.parentNode.removeChild(this._sugg.el);
    }
    this._sugg = null;
    document.removeEventListener('pointerdown', this._onDocPointerDown, true);
    window.removeEventListener('resize', this._onWinResize, true);
    window.removeEventListener('scroll', this._onViewScroll, true);
  }

  _handleOutsidePointer(e) {
    if (!this._sugg) return;
    const t = e.target;
    if (this._sugg.el.contains(t)) return;
    if (this.input === t) return;
    this._closeSuggest();
  }

  _handleScroll(e) {
    if (!this._sugg) return;
    const t = e && e.target;
    const insidePopover = !!(t && this._sugg.el.contains(t));
    // Ignore scrolls that originate inside the popover itself (it's
    // internally scrollable).
    if (insidePopover) return;
    // Any ancestor scroll closes — the popover is position:fixed so it
    // would otherwise detach visually from the caret.
    this._closeSuggest();
  }

  // ── History ────────────────────────────────────────────────────────────
  _pushHistory(q) {
    q = String(q || '').trim();
    if (!q) return;
    const list = this._history.filter(e => e !== q);
    list.unshift(q);
    if (list.length > 20) list.length = 20;
    this._history = list;
    TimelineQueryEditor._saveHistory(this._history);
  }

  // History menu is keyboard-first: a persistent `_historyMenu` handle
  // tracks the mounted menu + selected index so the editor's `_onKeyDown`
  // can drive it without stealing focus from the <textarea>. Pointer
  // hover mirrors keyboard selection so mouse + keys stay in sync.
  //
  // NB: deliberately NOT named `_hist` — that's the undo/redo ring (an
  // array of `{value, selStart, selEnd}` frames, see line ~109). Reusing
  // the same property name nuked the undo ring whenever the dropdown
  // closed (`onDismiss` set it to null), so the very next keystroke
  // crashed `_snapshotHistory` with `this._hist is null`.
  _isHistoryOpen() { return !!(this._historyMenu && this._historyMenu.el && this._historyMenu.el.parentNode); }

  _openHistoryMenu() {
    this._closeSuggest();
    this._closeHistoryMenu();
    if (!this._history.length) {
      this._openTransientBubble(this.historyBtn, 'No history yet — press Enter to save a query.');
      return;
    }
    const menu = document.createElement('div');
    menu.className = 'tl-query-hist-menu';
    menu.setAttribute('role', 'listbox');
    this._historyMenu = { el: menu, sel: 0, items: this._history.slice() };
    for (let i = 0; i < this._history.length; i++) {
      const q = this._history[i];
      const row = document.createElement('div');
      row.className = 'tl-query-hist-item' + (i === 0 ? ' tl-query-hist-item-active' : '');
      row.setAttribute('role', 'option');
      row.dataset.idx = String(i);
      row.textContent = q;
      row.title = q;
      row.addEventListener('pointerdown', (e) => {
        e.preventDefault();
        if (!this._historyMenu) return;
        this._historyMenu.sel = i;
        this._applyHistorySel();
      });
      // Hover syncs keyboard selection so mouse + keys can't desync.
      row.addEventListener('pointermove', () => {
        if (!this._historyMenu || this._historyMenu.sel === i) return;
        this._setHistorySel(i);
      });
      menu.appendChild(row);
    }
    this._mountFloatingMenu(menu, this.historyBtn, { onDismiss: () => { this._historyMenu = null; } });
    // Keep focus on the textarea so the editor's _onKeyDown keeps
    // receiving arrow / Enter / Escape.
    this.input.focus();
  }

  _setHistorySel(i) {
    if (!this._historyMenu) return;
    const n = this._historyMenu.items.length;
    if (!n) return;
    const next = ((i % n) + n) % n;
    if (next === this._historyMenu.sel) return;
    const rows = this._historyMenu.el.querySelectorAll('.tl-query-hist-item');
    if (rows[this._historyMenu.sel]) rows[this._historyMenu.sel].classList.remove('tl-query-hist-item-active');
    this._historyMenu.sel = next;
    if (rows[next]) {
      rows[next].classList.add('tl-query-hist-item-active');
      rows[next].scrollIntoView({ block: 'nearest' });
    }
  }

  _moveHistorySel(d) { if (this._historyMenu) this._setHistorySel(this._historyMenu.sel + d); }

  _applyHistorySel() {
    if (!this._historyMenu) return;
    const q = this._historyMenu.items[this._historyMenu.sel];
    this._closeHistoryMenu();
    if (q == null) return;
    this.setValue(q);
    this._scheduleCommit(true);
    this.input.focus();
  }

  _closeHistoryMenu() {
    const existing = document.querySelector('.tl-query-hist-menu');
    // Trigger the dismiss handler (which removes DOM + cleans up document
    // listeners) rather than just ripping the element out of the DOM.
    if (existing) {
      if (typeof existing._dismiss === 'function') existing._dismiss();
      else if (existing.parentNode) existing.parentNode.removeChild(existing);
    }
    this._historyMenu = null;
  }

  _openHelpPopover() {
    const existing = document.querySelector('.tl-query-help-menu');
    if (existing) { existing.parentNode.removeChild(existing); return; }
    this._closeSuggest();
    const menu = document.createElement('div');
    menu.className = 'tl-query-help-menu';
    menu.innerHTML = `
      <div class="tl-query-help-title">Query language</div>
      <div class="tl-query-help-body">
        <div><code>foo</code> — any column contains <i>foo</i></div>
        <div><code>col:foo</code> — column contains <i>foo</i></div>
        <div><code>col=foo</code> — column equals <i>foo</i> (<code>!=</code> for not equals)</div>
        <div><code>col~/re/i</code> — column matches regex</div>
        <div><code>col&gt;10</code> <code>col&gt;=10</code> <code>col&lt;10</code> — numeric / time compare</div>
        <div><code>AND</code> <code>OR</code> <code>NOT</code> <code>(…)</code> — booleans + grouping</div>
        <div><code>-foo</code> — shorthand for <code>NOT foo</code></div>
        <div><code>"foo bar"</code> — phrase</div>
        <div><code>[Event ID]:4624</code> — name with spaces</div>
        <div><code>is:sus</code> — rows matching a 🚩 suspicious mark</div>
        <div><code>is:detection</code> — rows matching a detection (EVTX)</div>
        <div style="margin-top:4px;opacity:.7">Ctrl/⌘-Space to show suggestions · Esc to dismiss · Tab / Enter to accept · Ctrl/⌘-↓ to open history</div>
        <div style="margin-top:2px;opacity:.7">Ctrl/⌘-Z to undo · Ctrl/⌘-Shift-Z (or Ctrl-Y) to redo · Ctrl/⌘-Backspace to delete the clause left of the caret</div>
      </div>
    `;
    this._mountFloatingMenu(menu, this.helpBtn);
  }

  _openTransientBubble(anchor, text) {
    const bub = document.createElement('div');
    bub.className = 'tl-query-bubble';
    bub.textContent = text;
    const rect = anchor.getBoundingClientRect();
    bub.style.position = 'fixed';
    // Left-anchored because the clear / history / help buttons live on
    // the LEFT edge of the query bar — aligning under the button's left
    // edge keeps the bubble in view. (The old right-anchor assumed the
    // buttons were flush-right and opened off-screen once they moved.)
    bub.style.left = Math.max(8, rect.left) + 'px';
    bub.style.top = (rect.bottom + 2) + 'px';
    bub.style.zIndex = '10001';
    document.body.appendChild(bub);
    setTimeout(() => { if (bub.parentNode) bub.parentNode.removeChild(bub); }, 1800);
  }

  // Shared mount helper for history / help / date-range menus — same
  // dismiss rules as the suggestion popover (outside pointerdown,
  // Escape, window resize). `opts.onDismiss` (optional) fires once the
  // menu is removed, so callers can null out their state pointer
  // without polling.
  _mountFloatingMenu(menu, anchor, opts) {
    const onDismiss = (opts && typeof opts.onDismiss === 'function') ? opts.onDismiss : null;
    const rect = anchor.getBoundingClientRect();
    menu.style.position = 'fixed';
    menu.style.top = (rect.bottom + 2) + 'px';
    menu.style.zIndex = '10001';
    document.body.appendChild(menu);
    // Left-align under the button (see _openTransientBubble for why),
    // but clamp to the viewport so a wide popover near the right edge
    // doesn't overflow. `offsetWidth` is only meaningful after the menu
    // is in the DOM — hence the appendChild call above.
    const menuW = menu.offsetWidth || 240;
    const maxLeft = Math.max(8, window.innerWidth - menuW - 8);
    menu.style.left = Math.max(8, Math.min(rect.left, maxLeft)) + 'px';

    let dismissed = false;
    const dismiss = () => {
      if (dismissed) return;
      dismissed = true;
      if (menu.parentNode) menu.parentNode.removeChild(menu);
      document.removeEventListener('pointerdown', onPointer, true);
      document.removeEventListener('keydown', onKey, true);
      window.removeEventListener('resize', onResize, true);
      if (onDismiss) { try { onDismiss(); } catch (_) { /* noop */ } }
    };
    // Expose dismiss so _closeHistoryMenu can invoke it cleanly.
    menu._dismiss = dismiss;
    const onPointer = (e) => { if (!menu.contains(e.target) && e.target !== anchor) dismiss(); };
    const onKey = (e) => { if (e.key === 'Escape') { e.preventDefault(); dismiss(); } };
    const onResize = () => dismiss();
    // Defer binding so the click that opened us doesn't immediately close.
    setTimeout(() => {
      document.addEventListener('pointerdown', onPointer, true);
      document.addEventListener('keydown', onKey, true);
      window.addEventListener('resize', onResize, true);
    }, 0);
  }

  // ── Inline datetime range widget ─────────────────────────────────────
  // The compact button + popover that replaces the old `tl-range-banner`.
  // `_window` is the editor's local copy of the view's `_window`; the
  // view pushes updates here via `setWindow` (scrubber/chart drag, reset),
  // and the popover commits user input back through `onWindowChange`
  // (which the view wires to mutate `_window` + run `_applyWindowOnly`).
  //
  // The button has two render modes:
  //   - empty   (`_window == null`): single line "🕒 Any time ▾"
  //   - active  (`_window != null`): three lines — start, end, delta.
  // A `--preview` modifier is applied during live drag so the analyst
  // can see the pending range hasn't been committed yet.

  // Public API. Render-only — does NOT call `onWindowChange` (the caller
  // is the source of truth). Pass `{preview: true}` for drag previews.
  setWindow(win) {
    if (!win) {
      this._window = null;
      this._windowPreview = false;
    } else {
      this._window = { min: win.min, max: win.max };
      this._windowPreview = !!win.preview;
    }
    this._renderDaterangeButton();
  }

  getWindow() {
    return this._window ? { min: this._window.min, max: this._window.max } : null;
  }

  // Internal — emit a window change to the view. The view applies it
  // and is expected to call `setWindow` back at us as part of its
  // render pass; we update locally first so the button repaints
  // immediately (before the view's rAF), avoiding a one-frame flicker.
  _commitWindow(win) {
    this._window = win ? { min: win.min, max: win.max } : null;
    this._windowPreview = false;
    this._renderDaterangeButton();
    try { this.onWindowChange(this._window ? { ...this._window } : null); } catch (_) { /* noop */ }
  }

  _isNumericAxis() {
    const f = this.formatters;
    return !!(f && typeof f.isNumeric === 'function' && f.isNumeric());
  }

  _formatStamp(v) {
    const f = this.formatters;
    if (typeof f.formatTimestamp === 'function') return f.formatTimestamp(v, this._isNumericAxis());
    if (Number.isFinite(v)) return String(v);
    return '—';
  }

  _formatSpan(min, max) {
    const f = this.formatters;
    const span = max - min;
    if (this._isNumericAxis()) {
      if (typeof f.formatNumeric === 'function' && Number.isFinite(span)) {
        return '· Δ ' + f.formatNumeric(span, span);
      }
      return Number.isFinite(span) ? '· Δ ' + String(span) : '';
    }
    if (typeof f.formatDuration === 'function') {
      const dur = f.formatDuration(span);
      return dur ? '· ' + dur : '';
    }
    return '';
  }

  _renderDaterangeButton() {
    if (!this.daterangeBtn || !this.daterangeBody) return;
    const btn = this.daterangeBtn;
    btn.classList.toggle('tl-query-daterange--active', !!this._window);
    btn.classList.toggle('tl-query-daterange--preview', !!this._windowPreview);
    if (!this._window) {
      this.daterangeBody.innerHTML = '<span class="tl-query-daterange-empty">🕒 Any time ▾</span>';
      btn.title = 'Filter by time range — click to set absolute / relative';
      return;
    }
    const lo = this._formatStamp(this._window.min);
    const hi = this._formatStamp(this._window.max);
    const delta = this._formatSpan(this._window.min, this._window.max);
    this.daterangeBody.innerHTML = `
      <span class="tl-query-daterange-active">
        <span class="tl-query-daterange-from">${_tlEsc(lo)}</span>
        <span class="tl-query-daterange-to">${_tlEsc(hi)}</span>
        <span class="tl-query-daterange-delta">${_tlEsc(delta)}</span>
      </span>
    `;
    btn.title = `Showing ${lo} → ${hi}${delta ? ' ' + delta : ''} — click to edit`;
  }

  // ── Date range popover ───────────────────────────────────────────────
  // Tabbed popover: Absolute (datetime-local OR number inputs + presets),
  // Relative (single-term "Last <N><unit>", date-axis only). Both tabs
  // share a draft `{min, max}` so toggling between them doesn't lose
  // state. Apply commits via `_commitWindow`; Clear commits null. Esc /
  // outside-pointer / window-resize dismisses without committing.
  _isDatePopoverOpen() { return !!(this._datePopover && this._datePopover.parentNode); }

  _toggleDatePopover() {
    if (this._isDatePopoverOpen()) {
      this._closeDatePopover();
      return;
    }
    this._openDatePopover();
  }

  _closeDatePopover() {
    if (this._datePopover && typeof this._datePopover._dismiss === 'function') {
      this._datePopover._dismiss();
    } else if (this._datePopover && this._datePopover.parentNode) {
      this._datePopover.parentNode.removeChild(this._datePopover);
    }
    this._datePopover = null;
  }

  _openDatePopover() {
    this._closeSuggest();
    this._closeHistoryMenu();
    const numeric = this._isNumericAxis();
    const dr = (this.formatters && typeof this.formatters.dataRange === 'function')
      ? this.formatters.dataRange() : null;
    // Draft state — start from the current window if any, else the data
    // range so the inputs are pre-populated with a sensible default.
    const draft = {
      min: this._window ? this._window.min
        : (dr && Number.isFinite(dr.min) ? dr.min : NaN),
      max: this._window ? this._window.max
        : (dr && Number.isFinite(dr.max) ? dr.max : NaN),
    };

    const menu = document.createElement('div');
    menu.className = 'tl-query-daterange-popover';
    menu.innerHTML = `
      <div class="tl-query-daterange-tabs" role="tablist">
        <button type="button" role="tab" data-tab="absolute" class="tl-query-daterange-tab tl-query-daterange-tab-active">Absolute</button>
        ${numeric ? '' : '<button type="button" role="tab" data-tab="relative" class="tl-query-daterange-tab">Relative</button>'}
      </div>
      <div class="tl-query-daterange-pane tl-query-daterange-pane-absolute" data-pane="absolute">
        <label class="tl-query-daterange-row">
          <span class="tl-query-daterange-row-label">From</span>
          ${numeric
    ? '<input type="number" step="any" class="tl-query-daterange-input" data-field="min">'
    : '<input type="datetime-local" step="1" class="tl-query-daterange-input" data-field="min">'}
        </label>
        <label class="tl-query-daterange-row">
          <span class="tl-query-daterange-row-label">To</span>
          ${numeric
    ? '<input type="number" step="any" class="tl-query-daterange-input" data-field="max">'
    : '<input type="datetime-local" step="1" class="tl-query-daterange-input" data-field="max">'}
        </label>
        <div class="tl-query-daterange-presets">
          ${this._presetChipsHtml(numeric)}
        </div>
      </div>
      ${numeric ? '' : `
      <div class="tl-query-daterange-pane tl-query-daterange-pane-relative" data-pane="relative" hidden>
        <div class="tl-query-daterange-rel-row">
          <span class="tl-query-daterange-row-label">Last</span>
          <input type="text" class="tl-query-daterange-rel-input"
                 data-field="rel" placeholder="e.g. 15m · 2h · 7d" autocomplete="off" spellcheck="false">
        </div>
        <div class="tl-query-daterange-rel-help">
          Single term — &lt;number&gt;&lt;unit&gt;. Units: <code>s</code> · <code>m</code> · <code>h</code> · <code>d</code> · <code>w</code>.
          Anchored to the data's latest timestamp.
        </div>
      </div>`}
      <div class="tl-query-daterange-foot">
        <button type="button" class="tl-query-daterange-foot-btn tl-query-daterange-clear">Clear</button>
        <span class="tl-query-daterange-foot-spacer"></span>
        <button type="button" class="tl-query-daterange-foot-btn tl-query-daterange-cancel">Cancel</button>
        <button type="button" class="tl-query-daterange-foot-btn tl-query-daterange-apply tl-query-daterange-foot-btn-primary">Apply</button>
      </div>
    `;

    // Pre-fill the absolute inputs from the draft.
    const minInput = menu.querySelector('[data-field="min"]');
    const maxInput = menu.querySelector('[data-field="max"]');
    if (numeric) {
      if (Number.isFinite(draft.min)) minInput.value = String(draft.min);
      if (Number.isFinite(draft.max)) maxInput.value = String(draft.max);
    } else {
      if (Number.isFinite(draft.min)) minInput.value = TimelineQueryEditor._toDateTimeLocal(draft.min);
      if (Number.isFinite(draft.max)) maxInput.value = TimelineQueryEditor._toDateTimeLocal(draft.max);
    }

    // Tab switching.
    const tabs = menu.querySelectorAll('.tl-query-daterange-tab');
    const panes = menu.querySelectorAll('.tl-query-daterange-pane');
    for (const tab of tabs) {
      tab.addEventListener('click', () => {
        const id = tab.dataset.tab;
        for (const t of tabs) t.classList.toggle('tl-query-daterange-tab-active', t === tab);
        for (const p of panes) p.hidden = p.dataset.pane !== id;
      });
    }

    // Preset chips — click sets both inputs and immediately commits.
    menu.querySelectorAll('.tl-query-daterange-preset').forEach(chip => {
      chip.addEventListener('click', () => {
        const win = this._resolvePreset(chip.dataset.preset, dr, numeric);
        if (!win) return;
        this._commitWindow(win);
        this._closeDatePopover();
      });
    });

    // Apply button — read the active pane's inputs into a window.
    menu.querySelector('.tl-query-daterange-apply').addEventListener('click', () => {
      const activeTab = menu.querySelector('.tl-query-daterange-tab-active').dataset.tab;
      let win = null;
      if (activeTab === 'absolute') {
        const lo = this._readAbsoluteInput(minInput, numeric);
        const hi = this._readAbsoluteInput(maxInput, numeric);
        if (!Number.isFinite(lo) || !Number.isFinite(hi) || hi <= lo) return;
        win = { min: lo, max: hi };
      } else {
        const relInput = menu.querySelector('[data-field="rel"]');
        const dur = (this.formatters && typeof this.formatters.parseRelative === 'function')
          ? this.formatters.parseRelative(relInput.value) : null;
        if (!dur) return;
        const anchor = (dr && Number.isFinite(dr.max)) ? dr.max : Date.now();
        win = { min: anchor - dur, max: anchor };
      }
      // Clamp to the data range so a sloppy "year 2099" entry doesn't
      // produce an empty grid.
      if (dr) {
        if (Number.isFinite(dr.min)) win.min = Math.max(dr.min, win.min);
        if (Number.isFinite(dr.max)) win.max = Math.min(dr.max, win.max);
      }
      if (!(Number.isFinite(win.min) && Number.isFinite(win.max) && win.max > win.min)) return;
      this._commitWindow(win);
      this._closeDatePopover();
    });

    // Enter inside any input = Apply.
    menu.querySelectorAll('input').forEach(inp => {
      inp.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          menu.querySelector('.tl-query-daterange-apply').click();
        }
      });
    });

    // Cancel / Clear.
    menu.querySelector('.tl-query-daterange-cancel').addEventListener('click', () => {
      this._closeDatePopover();
    });
    menu.querySelector('.tl-query-daterange-clear').addEventListener('click', () => {
      this._commitWindow(null);
      this._closeDatePopover();
    });

    this._datePopover = menu;
    this._mountFloatingMenu(menu, this.daterangeBtn, { onDismiss: () => { this._datePopover = null; } });
    // Focus the first input so keyboard analysts can start typing
    // immediately without a tab.
    setTimeout(() => {
      const first = menu.querySelector('input');
      if (first) first.focus();
    }, 0);
  }

  _presetChipsHtml(numeric) {
    if (numeric) {
      // Numeric-axis: only "Full range" makes sense as a preset; the
      // others are wall-clock relative and have no meaning here.
      return [
        '<button type="button" class="tl-query-daterange-preset" data-preset="full">Full range</button>',
        '<button type="button" class="tl-query-daterange-preset" data-preset="num-first-half">First half</button>',
        '<button type="button" class="tl-query-daterange-preset" data-preset="num-last-half">Last half</button>',
      ].join('');
    }
    const presets = [
      ['15m', 'Last 15m'],
      ['1h', 'Last 1h'],
      ['24h', 'Last 24h'],
      ['7d', 'Last 7d'],
      ['30d', 'Last 30d'],
      ['day', 'This day'],
      ['week', 'This week'],
      ['full', 'Full range'],
    ];
    return presets.map(([id, label]) =>
      `<button type="button" class="tl-query-daterange-preset" data-preset="${id}">${_tlEsc(label)}</button>`
    ).join('');
  }

  _resolvePreset(id, dr, numeric) {
    if (numeric) {
      if (!dr || !Number.isFinite(dr.min) || !Number.isFinite(dr.max)) return null;
      if (id === 'full') return { min: dr.min, max: dr.max };
      const mid = dr.min + (dr.max - dr.min) / 2;
      if (id === 'num-first-half') return { min: dr.min, max: mid };
      if (id === 'num-last-half') return { min: mid, max: dr.max };
      return null;
    }
    const anchor = (dr && Number.isFinite(dr.max)) ? dr.max : Date.now();
    const dataMin = (dr && Number.isFinite(dr.min)) ? dr.min : -Infinity;
    if (id === 'full') {
      if (!dr || !Number.isFinite(dr.min) || !Number.isFinite(dr.max)) return null;
      return { min: dr.min, max: dr.max };
    }
    if (id === 'day' || id === 'week') {
      // Anchor a calendar-aligned day / week to the latest data
      // timestamp so "This day" matches the rightmost histogram bucket.
      const d = new Date(anchor);
      const startOfDay = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
      if (id === 'day') return { min: Math.max(dataMin, startOfDay), max: anchor };
      // Week: ISO week starts Monday. `getUTCDay()` Sunday=0 → shift.
      const dow = (d.getUTCDay() + 6) % 7;
      const startOfWeek = startOfDay - dow * 86_400_000;
      return { min: Math.max(dataMin, startOfWeek), max: anchor };
    }
    // Otherwise it's a relative term ("15m", "24h", ...).
    const dur = (this.formatters && typeof this.formatters.parseRelative === 'function')
      ? this.formatters.parseRelative(id) : null;
    if (!dur) return null;
    return { min: Math.max(dataMin, anchor - dur), max: anchor };
  }

  _readAbsoluteInput(el, numeric) {
    if (!el) return NaN;
    const v = el.value;
    if (!v) return NaN;
    if (numeric) {
      const n = Number(v);
      return Number.isFinite(n) ? n : NaN;
    }
    // datetime-local — interpret as UTC to match the rest of the
    // timeline (which renders in UTC throughout — see
    // `_tlFormatFullUtc`). The browser hands us a local-tz string, but
    // since we display UTC the analyst's mental model is UTC; treat
    // the input as UTC-naive and parse with `Date.UTC`.
    const m = String(v).match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?$/);
    if (!m) return NaN;
    const ms = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0), m[7] ? Math.round(parseFloat('0.' + m[7]) * 1000) : 0);
    return Number.isFinite(ms) ? ms : NaN;
  }

  // Format an epoch-ms as a `datetime-local`-compatible string in UTC.
  // The browser's `<input type="datetime-local">` does not accept a `Z`
  // suffix; we display UTC throughout the timeline so the input value
  // is the UTC wall-clock spelled in the local-naive format.
  static _toDateTimeLocal(ms) {
    if (!Number.isFinite(ms)) return '';
    const d = new Date(ms);
    const pad = n => String(n).padStart(2, '0');
    return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
  }

  destroy() {
    this._closeSuggest();
    this._closeDatePopover();
    clearTimeout(this._debounceTimer);
    if (this.root && this.root.parentNode) this.root.parentNode.removeChild(this.root);
    // Drop back-references so the parent TimelineView (and its row data)
    // can be collected even if the editor instance lingers in a closure.
    this.view = null;
    this.onChange = null;
    this.onCommit = null;
    this.onWindowChange = null;
    this.formatters = null;
  }

  static _loadHistory() {
    const arr = safeStorage.getJSON(TIMELINE_KEYS.QUERY_HISTORY, []);
    return Array.isArray(arr) ? arr.filter(x => typeof x === 'string') : [];
  }
  static _saveHistory(list) {
    safeStorage.setJSON(TIMELINE_KEYS.QUERY_HISTORY, list || []);
  }

}


// ════════════════════════════════════════════════════════════════════════════
