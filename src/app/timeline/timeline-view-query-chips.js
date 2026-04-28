'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-query-chips.js — TimelineView prototype mixin (B2f3).
//
// Hosts the query-AST manipulation surface plus the chips strip
// renderer. Since the query bar became the SINGLE SOURCE OF TRUTH
// for row filtering, every click-pivot in the UI (right-click
// Include / Exclude / Only, column-card click, column-menu Apply,
// pivot drill-down, detection drill, legend click) goes through one
// of the AST-edit helpers here rather than mutating a parallel chip
// list. The "chips" rendered in the strip are derived from the AST,
// not stored independently.
//
// Methods (~21 instance):
//
//   Chips strip render:
//     _renderChips
//
//   AST read / commit primitives:
//     _queryCurrentAst,
//     _queryTopLevelClauses,
//     _queryClausesToAst,
//     _queryCommitClauses,
//     _clauseTargetsCol
//
//   AST edit helpers (the click-pivot mutators):
//     _queryAddClause,
//     _queryDropContradictions,
//     _queryToggleEqClause,
//     _queryToggleNeClause,
//     _queryReplaceContainsForCol,
//     _queryReplaceEqForCol,
//     _queryReplaceNotInForCol,
//     _queryReplaceAllForCol,
//     _queryRemoveClausesForCols
//
//   Chip operations (thin wrappers callers use as semantic verbs):
//     _addOrToggleChip,
//     _addContainsChipsReplace,
//     _replaceEqChipsForCol
//
//   Ctrl+Click multi-select helpers:
//     _accumulateCtrlSelect,
//     _commitCtrlSelect,
//     _clearCtrlSelect,
//     _togglePinCol
//
// Bodies are moved byte-identically. The contradictions-drop pass
// (`_queryDropContradictions` — strips `eq A` if `ne A` is being
// added, and vice versa) is a load-bearing UX contract: without
// it, users would build self-contradicting queries from quick
// click-pivots. Pinned by parity test below.
//
// Loads AFTER timeline-view.js (which declares `class TimelineView`).
// ════════════════════════════════════════════════════════════════════════════

Object.assign(TimelineView.prototype, {

  // ── Chips ────────────────────────────────────────────────────────────────
  // The chips strip hosts the "＋ Add Suspicious Indicator" button —
  // anchored on the left via flex-shrink:0 so it never moves — and zero-
  // or-more 🚩 sus chips that flow to its right from `_susMarks`
  // (persisted by column name, tint-only — never filter rows). The
  // active time window got promoted to the banner above; row-filter
  // chips live in the query bar. So this strip is pure sus state.
  _renderChips() {
    const el = this._els.chips;
    el.innerHTML = '';

    // "＋ Add Sus" button — always rendered FIRST so sus chips flow to
    // its right and the button's left position stays stable as chips
    // are added / removed.
    const addBtn = document.createElement('button');
    addBtn.type = 'button';
    addBtn.className = 'tl-chip tl-chip-add';
    addBtn.innerHTML = `<span class="tl-chip-plus">＋</span><span class="tl-chip-val">Add Suspicious Indicator</span>`;
    addBtn.title = 'Flag a value as 🚩 suspicious (tint-only, does not filter rows)';
    addBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      this._openAddSusPopover(addBtn);
    });
    el.appendChild(addBtn);

    // Render sus marks from `_susMarks` (resolved to live colIdx). Note
    // that we iterate `_susMarks` directly (not the resolved list) so
    // the ⊗ handler can splice the PERSISTED index and keep the
    // by-name persistence stable. Marks whose column is currently
    // missing (extracted col removed etc.) stay persisted but don't
    // render — `_susMarksResolved()` drops them.
    for (let i = 0; i < this._susMarks.length; i++) {

      const m = this._susMarks[i];
      // "Any column" marks render with a synthetic "Any" column label and
      // always bind to the persisted index (they don't resolve to a live
      // colIdx). Column-scoped marks whose column has disappeared (e.g.
      // extracted col removed) stay persisted but don't render — mirrors
      // `_susMarksResolved()`.
      const isAny = m.any === true;
      if (!isAny) {
        const colIdx = this.columns.indexOf(m.colName);
        if (colIdx < 0) continue;
      }
      const chip = document.createElement('span');
      chip.className = 'tl-chip tl-chip-sus' + (isAny ? ' tl-chip-sus-any' : '');
      const label = isAny ? '＊ Any' : m.colName;
      chip.innerHTML = `<span class="tl-chip-col">${_tlEsc(label)}</span><span class="tl-chip-op">🚩</span><span class="tl-chip-val">${_tlEsc(m.val)}</span><button class="tl-chip-x" title="Remove">⊗</button>`;
      // Capture the mark *object* (not its index) so rapid double-removal
      // can't splice the wrong entry after an earlier splice shifted indices.
      const markRef = m;
      chip.querySelector('.tl-chip-x').addEventListener('click', () => {
        const idx = this._susMarks.indexOf(markRef);
        if (idx < 0) return;
        this._susMarks.splice(idx, 1);
        TimelineView._saveSusMarksFor(this._fileKey, this._susMarks);
        this._rebuildSusBitmap();
        this._recomputeFilter();
        this._scheduleRender(['chart', 'chips', 'grid', 'columns']);
      });
      el.appendChild(chip);
    }

    // Clear-all button — only when there's at least one sus mark. Mirrors
    // the per-chip ⊗ teardown (wipe _susMarks, persist, rebuild bitmap,
    // recompute filter, re-render). margin-left:auto pushes it to the
    // far right of the chips strip.
    if (this._susMarks.length > 0) {
      const clearBtn = document.createElement('button');
      clearBtn.type = 'button';
      clearBtn.className = 'tl-chips-clear';
      clearBtn.innerHTML = '✕ Clear';
      clearBtn.title = 'Remove all suspicious indicators';
      clearBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        this._susMarks = [];
        TimelineView._saveSusMarksFor(this._fileKey, []);
        this._rebuildSusBitmap();
        this._recomputeFilter();
        this._scheduleRender(['chart', 'chips', 'grid', 'columns']);
      });
      el.appendChild(clearBtn);
    }
  },
  // ── AST edit helpers ─────────────────────────────────────────────────────
  // The query bar is the single source of truth for row filtering, so every
  // click-pivot (right-click Include / Exclude / Only, column-card click,
  // column-menu Apply, pivot drill-down, detection drill, legend click)
  // must MUTATE THE QUERY STRING rather than push onto a parallel chip
  // list. These helpers do the plumbing: parse `_queryStr` into an AST,
  // manipulate the top-level AND clauses, serialize back with live column
  // names (`_tlFormatQuery` uses `this.columns` so extracted columns
  // round-trip) and push into the editor + `_applyQueryString`. Every
  // helper funnels through `_queryCommitClauses` so exactly one parse /
  // render cycle happens per user action.
  _queryCurrentAst() {
    const s = (this._queryStr || '').trim();
    if (!s) return { k: 'empty' };
    try {
      return _tlParseQuery(_tlTokenize(s), () => this.columns);
    } catch (_) {
      // Mid-edit parse error — treat as empty so callers can still add
      // clauses (serializer will produce a valid string overwriting the
      // broken one).
      return { k: 'empty' };
    }
  },
  _queryTopLevelClauses(ast) {
    if (!ast || ast.k === 'empty') return [];
    if (ast.k === 'and') return ast.children.slice();
    return [ast];
  },
  _queryClausesToAst(clauses) {
    if (!clauses.length) return { k: 'empty' };
    if (clauses.length === 1) return clauses[0];
    return { k: 'and', children: clauses };
  },
  _queryCommitClauses(clauses) {
    const ast = this._queryClausesToAst(clauses);
    const s = _tlFormatQuery(ast, this.columns);
    if (this._queryEditor) this._queryEditor.setValue(s);
    this._applyQueryString(s);
  },
  // Does a single top-level clause reference `colIdx`?
  _clauseTargetsCol(c, colIdx) {
    if (!c) return false;
    if (c.k === 'pred' || c.k === 'in') return c.colIdx === colIdx;
    return false;
  },

  // Append a clause to the top-level AND. `opts.dedupe` skips duplicates.
  _queryAddClause(node, opts) {
    opts = opts || {};
    const clauses = this._queryTopLevelClauses(this._queryCurrentAst());
    if (opts.dedupe) {
      const key = JSON.stringify(node);
      for (const c of clauses) if (JSON.stringify(c) === key) return;
    }
    clauses.push(node);
    this._queryCommitClauses(clauses);
  },

  // Strip any top-level clause that would directly contradict an incoming
  // `col <op> val` assertion from the click-pivot path (right-click
  // Include / Exclude, column-card click, etc.) so the resulting query
  // never ends up with something like `col = v AND col != v` (0 rows,
  // useless to the analyst). Only `eq` / `ne` / `in` clauses on the same
  // column are considered — everything else is left alone. `in` lists
  // have just the contradicting value stripped and collapse to a bare
  // `pred` when a single value remains, matching the collapse rules used
  // by `_queryToggleEqClause`.
  //
  // `forOp` is the op the CALLER is about to append:
  //   'eq' → strip clauses that forbid `valStr` (ne + positive-sense
  //           absence inside a NOT-IN list)
  //   'ne' → strip clauses that require `valStr` (eq + presence inside
  //           an IN list)
  _queryDropContradictions(clauses, colIdx, valStr, forOp) {
    const stripOp = forOp === 'eq' ? 'ne' : 'eq';
    const stripNeg = forOp === 'eq';   // eq → strip NOT-IN; ne → strip IN
    for (let i = clauses.length - 1; i >= 0; i--) {
      const c = clauses[i];
      if (!c || c.colIdx !== colIdx) continue;
      if (c.k === 'pred' && c.op === stripOp && String(c.val) === valStr) {
        clauses.splice(i, 1);
        continue;
      }
      if (c.k === 'in' && !!c.neg === stripNeg) {
        const ix = c.vals.indexOf(valStr);
        if (ix < 0) continue;
        const newVals = c.vals.slice(); newVals.splice(ix, 1);
        if (newVals.length === 0) {
          clauses.splice(i, 1);
        } else if (newVals.length === 1) {
          clauses[i] = { k: 'pred', colIdx, op: c.neg ? 'ne' : 'eq', val: newVals[0] };
        } else {
          clauses[i] = { k: 'in', colIdx, vals: newVals, neg: !!c.neg };
        }
      }
    }
  },

  // Toggle an eq match against `col = val`. Handles both `pred(eq)` and
  // positive `in` nodes: if the value is found inside an `in` list, it's
  // removed (collapsing to a bare eq if one value remains, dropping the
  // clause entirely if empty). If not present, folds away any opposing
  // `ne` / `NOT IN` on the same `(col, val)` pair (so Include-after-
  // Exclude clears the exclude rather than producing an unsatisfiable
  // `col = v AND col != v`) and appends a bare eq clause.
  _queryToggleEqClause(colIdx, val) {
    const clauses = this._queryTopLevelClauses(this._queryCurrentAst());
    const valStr = String(val);
    for (let i = 0; i < clauses.length; i++) {
      const c = clauses[i];
      if (c.k === 'pred' && c.op === 'eq' && c.colIdx === colIdx && String(c.val) === valStr) {
        clauses.splice(i, 1);
        this._queryCommitClauses(clauses);
        return;
      }
      if (c.k === 'in' && !c.neg && c.colIdx === colIdx) {
        const ix = c.vals.indexOf(valStr);
        if (ix >= 0) {
          const newVals = c.vals.slice(); newVals.splice(ix, 1);
          if (newVals.length === 0) clauses.splice(i, 1);
          else if (newVals.length === 1) clauses[i] = { k: 'pred', colIdx, op: 'eq', val: newVals[0] };
          else clauses[i] = { k: 'in', colIdx, vals: newVals, neg: false };
          this._queryCommitClauses(clauses);
          return;
        }
      }
    }
    this._queryDropContradictions(clauses, colIdx, valStr, 'eq');
    clauses.push({ k: 'pred', colIdx, op: 'eq', val: valStr });
    this._queryCommitClauses(clauses);
  },

  // Toggle a ne match against `col != val`. Symmetric with the eq path
  // above but never folds into an `in` list (DSL has no `NOT IN` toggle).
  // Folds away any opposing `eq` / `IN` on the same `(col, val)` pair so
  // Exclude-after-Include clears the include rather than producing an
  // unsatisfiable `col = v AND col != v`.
  _queryToggleNeClause(colIdx, val) {
    const clauses = this._queryTopLevelClauses(this._queryCurrentAst());
    const valStr = String(val);
    for (let i = 0; i < clauses.length; i++) {
      const c = clauses[i];
      if (c.k === 'pred' && c.op === 'ne' && c.colIdx === colIdx && String(c.val) === valStr) {
        clauses.splice(i, 1);
        this._queryCommitClauses(clauses);
        return;
      }
    }
    this._queryDropContradictions(clauses, colIdx, valStr, 'ne');
    clauses.push({ k: 'pred', colIdx, op: 'ne', val: valStr });
    this._queryCommitClauses(clauses);
  },

  // Strip existing `col : text` contains clauses, then optionally append a
  // new one. Contains is "replace on column" by convention (legacy
  // `_addContainsChipsReplace` semantics).
  _queryReplaceContainsForCol(colIdx, text) {
    const clauses = this._queryTopLevelClauses(this._queryCurrentAst())
      .filter(c => !(c.k === 'pred' && c.op === 'contains' && c.colIdx === colIdx));
    if (text) clauses.push({ k: 'pred', colIdx, op: 'contains', val: String(text) });
    this._queryCommitClauses(clauses);
  },

  // Strip every eq / in / ne clause on this column, then install a fresh
  // set. 0 values → clears; 1 value → `col = v`; ≥ 2 values → `col IN (…)`.
  _queryReplaceEqForCol(colIdx, values) {
    const clauses = this._queryTopLevelClauses(this._queryCurrentAst())
      .filter(c => !(
        (c.k === 'pred' && (c.op === 'eq' || c.op === 'ne') && c.colIdx === colIdx) ||
        (c.k === 'in' && c.colIdx === colIdx)
      ));
    const vals = (values || []).map(v => String(v));
    const seen = new Set();
    const dedup = [];
    for (const v of vals) if (!seen.has(v)) { seen.add(v); dedup.push(v); }
    if (dedup.length === 1) {
      clauses.push({ k: 'pred', colIdx, op: 'eq', val: dedup[0] });
    } else if (dedup.length >= 2) {
      clauses.push({ k: 'in', colIdx, vals: dedup, neg: false });
    }
    this._queryCommitClauses(clauses);
  },

  // Column-menu companion: install a NEGATIVE set (`col != v` / `col NOT IN
  // (…)`). 0 values → clears; 1 value → `col != v`; ≥ 2 → `col NOT IN (…)`.
  // Strips the same family of eq/in/ne clauses as `_queryReplaceEqForCol`
  // so the two helpers are interchangeable end-state producers and the
  // Apply handler can pick whichever representation is shorter.
  _queryReplaceNotInForCol(colIdx, values) {
    const clauses = this._queryTopLevelClauses(this._queryCurrentAst())
      .filter(c => !(
        (c.k === 'pred' && (c.op === 'eq' || c.op === 'ne') && c.colIdx === colIdx) ||
        (c.k === 'in' && c.colIdx === colIdx)
      ));
    const vals = (values || []).map(v => String(v));
    const seen = new Set();
    const dedup = [];
    for (const v of vals) if (!seen.has(v)) { seen.add(v); dedup.push(v); }
    if (dedup.length === 1) {
      clauses.push({ k: 'pred', colIdx, op: 'ne', val: dedup[0] });
    } else if (dedup.length >= 2) {
      clauses.push({ k: 'in', colIdx, vals: dedup, neg: true });
    }
    this._queryCommitClauses(clauses);
  },

  // Strip every top-level clause referencing this column. Used by the
  // column menu's Reset button and by extracted-column removal.
  _queryReplaceAllForCol(colIdx) {
    const clauses = this._queryTopLevelClauses(this._queryCurrentAst())
      .filter(c => !this._clauseTargetsCol(c, colIdx));
    this._queryCommitClauses(clauses);
  },

  // Bulk variant — drop clauses targeting any of `colIndices`.
  _queryRemoveClausesForCols(colIndices) {
    const set = new Set(colIndices);
    const clauses = this._queryTopLevelClauses(this._queryCurrentAst())
      .filter(c => {
        if (c.k === 'pred' || c.k === 'in') return !set.has(c.colIdx);
        return true;
      });
    this._queryCommitClauses(clauses);
  },

  // ── Chip operations ──────────────────────────────────────────────────────
  // Thin dispatch wrappers. `op: 'sus'` writes to `_susMarks` (parallel
  // tint-only data model, persisted by column name). Everything else
  // mutates the query string via the AST-edit helpers above so the query
  // bar stays authoritative for row filtering.
  _addOrToggleChip(colIdx, val, opts) {
    const op = (opts && opts.op) || 'eq';
    const replace = !!(opts && opts.replace);
    if (op === 'sus') {
      const colName = this.columns[colIdx];
      if (colName == null) return;
      const valStr = String(val).toLowerCase();
      const ix = this._susMarks.findIndex(m => m.colName === colName && m.val.toLowerCase() === valStr);
      if (ix >= 0) this._susMarks.splice(ix, 1);
      else this._susMarks.push({ colName, val: valStr });
      TimelineView._saveSusMarksFor(this._fileKey, this._susMarks);
      this._rebuildSusBitmap();
      this._recomputeFilter();
      this._scheduleRender(['chart', 'chips', 'grid', 'columns']);
      return;
    }
    if (op === 'eq') {
      if (replace) this._queryReplaceEqForCol(colIdx, [val]);
      else this._queryToggleEqClause(colIdx, val);
      return;
    }
    if (op === 'ne') {
      this._queryToggleNeClause(colIdx, val);
      return;
    }
    if (op === 'contains') {
      // Contains on an "any" column (colIdx === -1) can't go through the
      // replace-for-col helper (it keys on colIdx). Fall through to the
      // generic add-clause path for the -1 case.
      if (colIdx === -1) {
        this._queryAddClause({ k: 'any', needle: String(val) }, { dedupe: true });
      } else {
        this._queryReplaceContainsForCol(colIdx, val);
      }
      return;
    }
  },

  _addContainsChipsReplace(colIdx, text) {
    this._queryReplaceContainsForCol(colIdx, text);
  },

  _replaceEqChipsForCol(colIdx, values) {
    this._queryReplaceEqForCol(colIdx, values);
  },

  // ── Ctrl+Click multi-select helpers ──────────────────────────────────────
  _accumulateCtrlSelect(colIdx, val, rowEl) {
    if (!this._pendingCtrlSelect || this._pendingCtrlSelect.colIdx !== colIdx) {
      this._clearCtrlSelect();
      this._pendingCtrlSelect = { colIdx, values: new Set(), rows: [] };
    }
    const p = this._pendingCtrlSelect;
    if (p.values.has(val)) {
      p.values.delete(val);
      rowEl.classList.remove('tl-col-row-selected');
    } else {
      p.values.add(val);
      rowEl.classList.add('tl-col-row-selected');
    }
    if (!p.values.size) this._pendingCtrlSelect = null;
  },

  _commitCtrlSelect() {
    if (!this._pendingCtrlSelect || !this._pendingCtrlSelect.values.size) return;
    const { colIdx, values } = this._pendingCtrlSelect;
    this._pendingCtrlSelect = null;
    this._queryReplaceEqForCol(colIdx, Array.from(values));
  },

  _clearCtrlSelect() {
    if (!this._pendingCtrlSelect) return;
    for (const r of this._pendingCtrlSelect.rows) r.classList.remove('tl-col-row-selected');
    const host = this._els && this._els.cols;
    if (host) host.querySelectorAll('.tl-col-row-selected').forEach(el => el.classList.remove('tl-col-row-selected'));
    this._pendingCtrlSelect = null;
  },

  _togglePinCol(colName) {
    const idx = this._pinnedCols.indexOf(colName);
    if (idx >= 0) this._pinnedCols.splice(idx, 1);
    else this._pinnedCols.push(colName);
    TimelineView._savePinnedColsFor(this._fileKey, this._pinnedCols);
    this._scheduleRender(['columns']);
  },

});
