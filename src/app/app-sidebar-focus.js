// ════════════════════════════════════════════════════════════════════════════
// App — sidebar click-to-focus / highlighting engine.
//
// Split out of app-sidebar.js so the file stays below ~2 K lines. This
// half owns everything that happens *after* the analyst clicks an IOC /
// YARA / encoded-content row in the sidebar: locating every match in the
// renderer's `_rawText` (or the DOM fallback), painting inline <mark>s,
// scrolling the current match into view, cycling the "current" index on
// repeat clicks, and clearing everything after the 5 s idle window. The
// Binary Metadata + MITRE ATT&CK Coverage sections live here too because
// their rows hang off the same navigation plumbing.
//
// See CONTRIBUTING.md Gotchas → "JS_FILES order" for the load-order rule:
// this file must load after app-sidebar.js (which owns _renderSidebar and
// the section builders that attach click handlers calling into the focus
// engine defined here).
// ════════════════════════════════════════════════════════════════════════════
Object.assign(App.prototype, {

  // ── Navigate to finding in content view ─────────────────────────────────
  //
  // Two unified click flows (see _highlightMatchesInline for the mechanics):
  //   • YARA match: highlight every string match returned by the engine.
  //   • IOC (URL / IP / hash / path / …): scan the rendered source text for
  //     every occurrence of the IOC value and highlight them all.
  // First click = highlight all + scroll-only-if-nothing-in-view.
  // Subsequent clicks (within 5 s) cycle `ref._currentMatchIndex` and always
  // scroll the current match into view. A 5 s no-click timer clears the
  // highlights and resets the index so the next click counts as "first" again.
  _navigateToFinding(ref, rowEl) {
    // Visual feedback — flash the clicked row
    rowEl.classList.add('ioc-flash');
    setTimeout(() => rowEl.classList.remove('ioc-flash'), 600);

    const pc = document.getElementById('page-container');
    const containerEl = pc && pc.firstElementChild;

    // Renderers with a Preview/Source toggle (HTML, SVG) expose
    // `_showSourcePane()` so the highlight surface is actually visible before
    // we try to scroll a <mark> into view.
    if (containerEl && typeof containerEl._showSourcePane === 'function') {
      try { containerEl._showSourcePane(); } catch (_) { /* best effort */ }
    }

    // ── YARA match: highlight ALL matches with click cycling ───────────────
    if (ref.type === IOC.YARA && ref._yaraMatches && ref._yaraMatches.length > 0) {
      const sourceText = containerEl && containerEl._rawText;
      const plaintextTable = pc && pc.querySelector('.plaintext-table');
      const matches = ref._yaraMatches;
      const totalMatches = matches.length;

      // First click = no current index tracked; subsequent clicks advance.
      const isFirstClick = (ref._currentMatchIndex === undefined);
      if (isFirstClick) {
        ref._currentMatchIndex = 0;
      } else {
        ref._currentMatchIndex = (ref._currentMatchIndex + 1) % totalMatches;
      }
      const focusIdx = ref._currentMatchIndex;
      const focusMatch = matches[focusIdx];

      // Match counter toast
      this._toast(`Match ${focusIdx + 1}/${totalMatches}: ${this._truncateToast(focusMatch.stringId)}`);

      if (plaintextTable && sourceText) {
        this._highlightMatchesInline(
          plaintextTable, sourceText, matches, focusIdx,
          /* forceScroll = */ !isFirstClick, ref, 'yara'
        );
        return;
      }

      // ── YARA match in CSV view: highlight in detail pane ──────────────────
      const csvView = pc && pc.querySelector('.csv-view');
      if (csvView && csvView._csvFilters && sourceText) {
        this._highlightYaraMatchesInCsv(
          csvView, sourceText, matches, focusIdx, /* forceScroll = */ !isFirstClick, ref
        );
        return;
      }
    }


    // Check if we have an EVTX view with filter controls
    const evtxView = pc && pc.querySelector('.evtx-view');
    if (evtxView && evtxView._evtxFilters) {
      const filters = evtxView._evtxFilters;

      // For IOC.PATTERN type: try to extract Event ID from the description
      if (ref.type === IOC.PATTERN || ref.type === IOC.INFO) {
        // Match patterns like "Event 1102:", "Sysmon Event 1:", "Defender Event 1006:", etc.
        const eidMatch = ref.url.match(/Event\s+(\d+)\s*:/);
        if (eidMatch) {
          // Apply Event ID filter
          filters.searchInput.value = '';
          filters.eidInput.value = eidMatch[1];
          filters.levelSelect.value = '';
          filters.applyFilters();
          // Expand ALL filtered rows for IOC navigation
          if (filters.expandAll) {
            filters.expandAll();
          }
          // Scroll the EVTX table into view
          filters.scrollContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
          // Flash the filter bar to draw attention
          const filterBar = evtxView.querySelector('.evtx-filter-bar');
          if (filterBar) {
            filterBar.classList.add('evtx-filter-flash');
            setTimeout(() => filterBar.classList.remove('evtx-filter-flash'), 1000);
          }
          // Subtle highlight of matched text inside expanded detail panes
          this._highlightIocInEvtxRows(evtxView, 'Event ' + eidMatch[1], ref);
          return;
        }
      }

      // For all other IOC types: use text search filter
      const searchVal = ref.url || '';
      if (searchVal) {
        // For hashes like "SHA256:ABCDEF...", just search the hash value part
        let highlightTerm = searchVal;
        const hashMatch = searchVal.match(/^(?:SHA256|SHA1|MD5|IMPHASH):(.+)$/i);
        if (hashMatch) highlightTerm = hashMatch[1];
        // For DOMAIN\User usernames, search just the username part (domain and
        // username are stored as separate fields in EVTX event data)
        if (ref.type === IOC.USERNAME && highlightTerm.includes('\\')) {
          highlightTerm = highlightTerm.split('\\').pop();
        }

        // Two terms: `highlightTerm` is the FULL value used for the detail-
        // pane <mark> wrapping — never truncated, otherwise long URLs /
        // tokens only get partially highlighted (the mark would end at
        // char 80, visually indistinguishable from "only the first wrapped
        // line is highlighted"). `searchTerm` is the 80-cap used ONLY for
        // the EVTX filter input, where an over-specific filter string can
        // miss rows whose joined text has subtle whitespace/escaping
        // differences vs. the IOC value.
        const searchTerm = highlightTerm.length > 80
          ? highlightTerm.substring(0, 80)
          : highlightTerm;

        filters.eidInput.value = '';
        filters.searchInput.value = searchTerm;
        filters.levelSelect.value = '';
        filters.applyFilters();
        // Expand ALL filtered rows for IOC navigation
        if (filters.expandAll) {
          filters.expandAll();
        }
        filters.scrollContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
        const filterBar = evtxView.querySelector('.evtx-filter-bar');
        if (filterBar) {
          filterBar.classList.add('evtx-filter-flash');
          setTimeout(() => filterBar.classList.remove('evtx-filter-flash'), 1000);
        }
        // Subtle highlight of matched text inside expanded detail panes.
        // Pass the full `highlightTerm` — _highlightIocInEvtxRows does an
        // indexOf and returns silently if not found verbatim, which is
        // correct fallback behaviour for the rare mismatch case.
        this._highlightIocInEvtxRows(evtxView, highlightTerm, ref);
        return;
      }
    }

    // Check if we have a CSV view — scroll to matching row and auto-expand
    const csvView = pc && pc.querySelector('.csv-view');
    if (csvView && csvView._csvFilters) {
      const filters = csvView._csvFilters;
      const searchVal = ref.url || '';
      if (searchVal && filters.dataRows && filters.dataRows.length > 0) {
        // For hashes like "SHA256:ABCDEF...", just search the hash value part
        let highlightTerm = searchVal;
        const hashMatch = searchVal.match(/^(?:SHA256|SHA1|MD5|IMPHASH):(.+)$/i);
        if (hashMatch) highlightTerm = hashMatch[1];

        // Two terms: `highlightTerm` is the FULL (hash-prefix-stripped) value
        // and is what gets wrapped in <mark> inside the detail pane — never
        // truncated, otherwise long URLs / tokens only get partially
        // highlighted (the visible mark ends at char 80, which usually falls
        // at/near a wrap boundary and gave the false impression that
        // word-wrapped lines weren't being highlighted at all).
        // `searchTerm` is the 80-char-capped version used ONLY for row-find;
        // the cap guards against overly specific matches when the joined row
        // text has subtle whitespace/escaping differences vs. the IOC value.
        const searchTerm = highlightTerm.length > 80
          ? highlightTerm.substring(0, 80)
          : highlightTerm;

        // Find matching row and use virtual scrolling API
        const term = searchTerm.toLowerCase();
        for (const r of filters.dataRows) {
          if (r.searchText && r.searchText.includes(term)) {
            // Use the new scrollToRow method for virtual scrolling
            if (filters.scrollToRow) {
              this._highlightIocInCsvRow(csvView, highlightTerm, r.dataIndex, ref);
            } else {
              // Fallback for non-virtual scrolling (shouldn't happen)
              filters.expandRow(r);
            }
            return;
          }
        }

        // Fallback: if exact row match not found, try partial match on first few chars
        const shortTerm = term.length > 20 ? term.substring(0, 20) : term;
        if (shortTerm !== term) {
          for (const r of filters.dataRows) {
            if (r.searchText && r.searchText.includes(shortTerm)) {
              if (filters.scrollToRow) {
                // Still pass the full `highlightTerm` — _wrapIocMarkInPane's
                // indexOf will simply return -1 if the full value isn't in
                // the cell verbatim, leaving the yellow row tint to signal
                // the match. Better than partially-highlighting with a
                // 20-char prefix.
                this._highlightIocInCsvRow(csvView, highlightTerm, r.dataIndex, ref);
              } else {
                filters.expandRow(r);
              }
              return;
            }
          }
        }
      }
    }

    // ── SQLite view ────────────────────────────────────────────────────────
    // The SQLite renderer embeds a GridViewer whose root is tagged
    // `.csv-view`, so the CSV branch above handles navigation. If the CSV
    // branch fell through (no match in the active tab), there is nothing
    // more we can do here — cross-tab IOC search is not yet supported.

    // ── IOC highlighting with click-cycle semantics ─────────────────────────
    //
    // Mirrors the YARA flow: find every occurrence of the IOC value in the
    // rendered source text, highlight all, first click scroll-only-if-none-in-
    // view, subsequent clicks cycle `ref._currentMatchIndex`, auto-clear 5 s
    // after the last click.
    //
    // Falls back silently when there is no source text surface available
    // (visual-only renderers like images, PDF pages, archive listings).
    const sourceText = containerEl && containerEl._rawText;
    const plaintextTable = pc && pc.querySelector('.plaintext-table');
    if (plaintextTable && sourceText) {
      const iocMatches = this._findIOCMatches(ref, sourceText);
      if (iocMatches.length) {
        const totalMatches = iocMatches.length;
        const isFirstClick = (ref._currentMatchIndex === undefined);
        if (isFirstClick) {
          ref._currentMatchIndex = 0;
        } else {
          ref._currentMatchIndex = (ref._currentMatchIndex + 1) % totalMatches;
        }
        const focusIdx = ref._currentMatchIndex;
        const focusValue = ref.url || iocMatches[focusIdx].value || '';
        this._toast(`Match ${focusIdx + 1}/${totalMatches}: ${this._truncateToast(focusValue)}`);

        this._highlightMatchesInline(
          plaintextTable, sourceText, iocMatches, focusIdx,
          /* forceScroll = */ !isFirstClick, ref, 'ioc'
        );
        return;
      }
    }

    // ── Fallback for non-plaintext content: TreeWalker-based highlighting ──
    // Best effort: flash the first occurrence of the IOC value anywhere in
    // the rendered DOM. No cycling / no inline marks persisting.
    if (pc && ref.url) {
      // For SafeLinks, search for the wrapper URL if available
      const searchText = ref._highlightText || ref.url;
      const textContent = pc.textContent || '';
      if (textContent.includes(searchText) || textContent.toLowerCase().includes(searchText.toLowerCase())) {
        try {
          const sel = window.getSelection();
          sel.removeAllRanges();
          // Walk text nodes to find the match
          const walker = document.createTreeWalker(pc, NodeFilter.SHOW_TEXT, null);
          const searchLower = searchText.toLowerCase();
          let node;
          while ((node = walker.nextNode())) {
            const idx = node.textContent.toLowerCase().indexOf(searchLower);
            if (idx >= 0) {
              const range = document.createRange();
              range.setStart(node, idx);
              range.setEnd(node, Math.min(idx + searchText.length, node.textContent.length));
              sel.addRange(range);
              node.parentElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
              // Flash highlight effect
              const mark = document.createElement('mark');
              mark.className = 'ioc-highlight ioc-highlight-flash';
              try { range.surroundContents(mark); } catch (_) { /* cross-boundary */ }
              setTimeout(() => {
                if (mark.parentNode) {
                  mark.replaceWith(...mark.childNodes);
                }
              }, 2000);
              return;
            }
          }
        } catch (_) { /* best effort */ }
      }
    }
    // Last resort: nothing visible to highlight. Fail silently — the sidebar
    // row-flash already gave click feedback.
  },

  // ── Build list of IOC occurrences in source text ────────────────────────
  //
  // Returns an array of {offset, length, value} entries covering every
  // occurrence of the IOC's highlight text within `sourceText`. Case-
  // insensitive search is used as a fallback if the exact-case search
  // yields no hits. The renderer-provided _sourceOffset/_sourceLength is
  // always included (deduped) so at least one guaranteed match is present.
  _findIOCMatches(ref, sourceText) {
    const matches = [];
    const seen = new Set(); // offsets already recorded

    const push = (offset, length, value) => {
      if (offset == null || length <= 0) return;
      if (offset < 0 || offset + length > sourceText.length) return;
      if (seen.has(offset)) return;
      seen.add(offset);
      matches.push({ offset, length, value: value || sourceText.substring(offset, offset + length) });
    };

    // 1. Authoritative location supplied by renderer, if any.
    if (ref._sourceOffset !== undefined && ref._sourceLength) {
      push(ref._sourceOffset, ref._sourceLength, null);
    }

    // 2. Every occurrence of the IOC value (or SafeLink wrapper).
    const searchText = ref._highlightText || ref.url;
    if (searchText && searchText.length > 0 && searchText.length <= 2048) {
      // Exact-case first.
      let from = 0;
      while (from <= sourceText.length) {
        const idx = sourceText.indexOf(searchText, from);
        if (idx === -1) break;
        push(idx, searchText.length, searchText);
        from = idx + Math.max(1, searchText.length);
      }
      // If nothing hit exact-case (common for URLs re-cased in HTML), try CI.
      if (matches.length === 0 || (matches.length === 1 && ref._sourceOffset !== undefined)) {
        const haystack = sourceText.toLowerCase();
        const needle = searchText.toLowerCase();
        let fromL = 0;
        while (fromL <= haystack.length) {
          const idx = haystack.indexOf(needle, fromL);
          if (idx === -1) break;
          push(idx, searchText.length,
            sourceText.substring(idx, idx + searchText.length));
          fromL = idx + Math.max(1, searchText.length);
        }
      }
    }

    // Sort by offset so cycling walks the document top-to-bottom.
    matches.sort((a, b) => a.offset - b.offset);
    return matches;
  },

  // ── Highlight ALL matches inline (character-level precision) ──────────
  //
  // `matches` is the full array of {offset, length, stringId, ...} entries.
  // `focusIdx` is the index of the match that should be scrolled to.
  // `forceScroll` is true when the user has cycled (always scroll the focus
  //   match into view); when false (first click), we only scroll if *no*
  //   currently-wrapped match is already visible in the viewport.
  // `ref` is the YARA/IOC ref so the 5-second timer can reset _currentMatchIndex.
  // `kind` is 'yara' | 'ioc' and selects the CSS classes used for the
  //   inline <mark>s and the line-background highlight.
  _highlightMatchesInline(table, sourceText, matches, focusIdx, forceScroll, ref, kind) {
    // Clear any existing match highlights + pending clear-timer first.
    this._clearMatchHighlight();

    // Resolve CSS classes for this highlight kind.
    // yara → blue marks + blue line bg; ioc → yellow marks + yellow line bg.
    const isIoc = kind === 'ioc';
    const markClass   = isIoc ? 'ioc-highlight'      : 'yara-highlight';
    const flashClass  = isIoc ? 'ioc-highlight-flash' : 'yara-highlight-flash';
    const lineClass   = isIoc ? 'ioc-highlight-line'  : 'yara-line-highlight';
    const dataAttr    = isIoc ? 'data-ioc-match'      : 'data-yara-match';
    const datasetKey  = isIoc ? 'iocMatch'            : 'yaraMatch';


    const rows = table.rows;

    // Soft-wrap map from plaintext-renderer.js — present on minified-JS
    // files where a single logical line is split across multiple <tr>s.
    // When absent (normal files), fall back to 1 row per logical line.
    const lineToFirstRow = table._lineToFirstRow || null;
    const wrapChunkSize  = (lineToFirstRow && table._chunkSize) ? table._chunkSize : 0;

    // ── 1. Compute (rowIdx, charPosWithinRow, length) for each match ────
    //    and group them by row so each row only gets a single rewrite.
    //    For soft-wrapped lines, a single YARA/IOC match on line N may
    //    span multiple chunk rows — expand it into one entry per row so
    //    the highlight renders continuously across the wrap boundary.
    const perMatch = [];
    const matchesByLine = new Map(); // rowIdx -> array of {charPos, length, matchIdx}
    for (let i = 0; i < matches.length; i++) {
      const m = matches[i];
      if (m.offset == null || !m.length) continue;
      const beforeText = sourceText.substring(0, m.offset);
      const lineIndex = (beforeText.match(/\n/g) || []).length;
      const lastNewline = beforeText.lastIndexOf('\n');
      const charInLine = lastNewline === -1 ? m.offset : m.offset - lastNewline - 1;

      if (lineToFirstRow && wrapChunkSize > 0) {
        // Translate (logicalLine, charInLine) → (rowIdx, charInRow).
        // When the match crosses a chunk boundary, split it across rows.
        const firstRow = lineToFirstRow[lineIndex];
        if (firstRow == null) continue;
        let remaining = m.length;
        let cursor    = charInLine;
        while (remaining > 0) {
          const rowIdx   = firstRow + Math.floor(cursor / wrapChunkSize);
          const charInRow = cursor % wrapChunkSize;
          if (rowIdx >= rows.length) break;
          const take = Math.min(remaining, wrapChunkSize - charInRow);
          perMatch.push({ matchIdx: i, lineIndex: rowIdx, charPos: charInRow, length: take });
          let arr = matchesByLine.get(rowIdx);
          if (!arr) { arr = []; matchesByLine.set(rowIdx, arr); }
          arr.push({ charPos: charInRow, length: take, matchIdx: i });
          cursor    += take;
          remaining -= take;
        }
      } else {
        // Normal 1-row-per-line path (unchanged behaviour).
        const charPos = charInLine;
        if (lineIndex >= rows.length) continue;
        perMatch.push({ matchIdx: i, lineIndex, charPos, length: m.length });
        let arr = matchesByLine.get(lineIndex);
        if (!arr) { arr = []; matchesByLine.set(lineIndex, arr); }
        arr.push({ charPos, length: m.length, matchIdx: i });
      }
    }
    if (!perMatch.length) return;

    // ── 2. For each affected line, insert <mark> elements for every match.
    //    Sort by charPos so we can walk the line text left-to-right.
    //    The generated <mark>s are tagged with the kind-specific data-attr
    //    (data-yara-match / data-ioc-match) so we can later locate the
    //    focus match for scrolling.
    const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    for (const [lineIndex, lineMatches] of matchesByLine) {
      const row = rows[lineIndex];
      const codeCell = row.querySelector('.plaintext-code');
      if (!codeCell) continue;

      // Sort left-to-right and drop overlapping matches (keep the first).
      lineMatches.sort((a, b) => a.charPos - b.charPos);
      const nonOverlapping = [];
      let cursor = -1;
      for (const lm of lineMatches) {
        if (lm.charPos >= cursor) {
          nonOverlapping.push(lm);
          cursor = lm.charPos + lm.length;
        }
      }

      const hasHighlighting = codeCell.innerHTML !== codeCell.textContent;

      if (hasHighlighting) {
        // Syntax-highlighted HTML: insert marks via TreeWalker for each match
        // in reverse order so earlier offsets stay valid.
        for (let i = nonOverlapping.length - 1; i >= 0; i--) {
          const lm = nonOverlapping[i];
          this._highlightInHtmlNode(codeCell, lm.charPos, lm.length, lm.matchIdx, kind);
        }
      } else {
        // Plain text cell: build a single innerHTML in one pass.
        const cellText = codeCell.textContent;
        let out = '';
        let pos = 0;
        for (const lm of nonOverlapping) {
          if (lm.charPos > cellText.length) break;
          const end = Math.min(lm.charPos + lm.length, cellText.length);
          if (lm.charPos > pos) out += esc(cellText.substring(pos, lm.charPos));
          const matchedText = cellText.substring(lm.charPos, end);
          out += `<mark class="${markClass} ${flashClass}" ${dataAttr}="${lm.matchIdx}">${esc(matchedText)}</mark>`;
          pos = end;
        }
        if (pos < cellText.length) out += esc(cellText.substring(pos));
        codeCell.innerHTML = out;
      }

      row.classList.add(lineClass);
    }

    // ── 3. Determine whether to scroll. ──────────────────────────────────
    //    On first click (forceScroll=false) we only scroll if *no* mark is
    //    currently visible in the viewport. On subsequent clicks we always
    //    scroll the focused match.
    const pc = document.getElementById('page-container');
    const allMarks = Array.from((pc || document).querySelectorAll('mark.' + markClass));
    const focusMark = allMarks.find(m => m.dataset[datasetKey] === String(focusIdx)) || allMarks[0];

    let shouldScroll = forceScroll;
    if (!forceScroll) {
      // Check if any mark intersects the current viewport.
      const vh = window.innerHeight || document.documentElement.clientHeight;
      const vw = window.innerWidth || document.documentElement.clientWidth;
      const anyInView = allMarks.some(m => {
        const r = m.getBoundingClientRect();
        return r.bottom > 0 && r.top < vh && r.right > 0 && r.left < vw && r.width > 0 && r.height > 0;
      });
      shouldScroll = !anyInView;
    }

    if (shouldScroll && focusMark) {
      focusMark.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    // ── 4. Schedule the 5-second clear timer. ────────────────────────────
    //    Any new click resets the timer (we cleared the previous one at the
    //    top of this method). When it fires, we remove all highlights and
    //    reset the ref's _currentMatchIndex so the NEXT click counts as a
    //    fresh "first click".
    this._matchHighlightTimer = setTimeout(() => {
      this._clearMatchHighlight();
      if (ref) ref._currentMatchIndex = undefined;
      this._matchHighlightTimer = null;
    }, 5000);
  },



  // ── Highlight within syntax-highlighted HTML content ────────────────────
  //
  // Optional `matchIdx` is stamped on the resulting <mark> as
  // `data-yara-match="<idx>"` (or `data-ioc-match` for kind='ioc') so
  // _highlightMatchesInline can locate the focus match for scrolling.
  _highlightInHtmlNode(container, charPos, length, matchIdx, kind) {
    const isIoc = kind === 'ioc';
    const markClass  = isIoc ? 'ioc-highlight'       : 'yara-highlight';
    const flashClass = isIoc ? 'ioc-highlight-flash' : 'yara-highlight-flash';
    const datasetKey = isIoc ? 'iocMatch'            : 'yaraMatch';

    // Collect every text node in the container with its running character
    // offset so we can locate which node(s) any match range intersects. This
    // correctly handles matches that span multiple text nodes — a common
    // situation when highlight.js tokenises paths like `C:\temp\update.exe`
    // into separate <span>s for each punctuation character.
    const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT, null);
    const segments = [];
    let runningPos = 0;
    let n;
    while ((n = walker.nextNode())) {
      const len = n.nodeValue.length;
      segments.push({ node: n, start: runningPos, end: runningPos + len });
      runningPos += len;
    }

    const matchEnd = charPos + length;
    const hits = [];
    for (const s of segments) {
      if (s.end <= charPos) continue;
      if (s.start >= matchEnd) break;
      const localStart = Math.max(0, charPos - s.start);
      const localEnd   = Math.min(s.end - s.start, matchEnd - s.start);
      if (localEnd > localStart) hits.push({ seg: s, localStart, localEnd });
    }
    if (!hits.length) return;

    // Wrap each intersecting slice in its own <mark>, walking in reverse so
    // splitText() calls on earlier nodes don't invalidate offsets of later
    // hits. All generated marks share the same matchIdx/dataset attribute so
    // focus-scrolling + cross-flash can locate any of them.
    for (let i = hits.length - 1; i >= 0; i--) {
      const h = hits[i];
      const tn = h.seg.node;
      // Detach the tail that lies after the match region, if any.
      if (h.localEnd < tn.nodeValue.length) tn.splitText(h.localEnd);
      // Detach the head that lies before the match region, if any; the
      // returned node then represents exactly the matched slice.
      let targetNode = tn;
      if (h.localStart > 0) targetNode = tn.splitText(h.localStart);
      const mark = document.createElement('mark');
      mark.className = markClass + ' ' + flashClass;
      if (matchIdx !== undefined) mark.dataset[datasetKey] = String(matchIdx);
      targetNode.parentNode.insertBefore(mark, targetNode);
      mark.appendChild(targetNode);
    }
  },



  // ── Clear YARA + IOC inline highlights ──────────────────────────────────
  //
  // Single clear-all for both YARA (blue) and IOC (yellow) match highlights.
  // Cancels any pending auto-clear timer (unified `_matchHighlightTimer`).
  _clearMatchHighlight() {
    // Cancel any pending auto-clear timer so it doesn't fire later and
    // reset an unrelated ref's _currentMatchIndex.
    if (this._matchHighlightTimer) {
      clearTimeout(this._matchHighlightTimer);
      this._matchHighlightTimer = null;
    }

    const pc = document.getElementById('page-container');
    if (!pc) return;

    // Remove line-background highlights (both kinds)
    const highlightedLines = pc.querySelectorAll('.yara-line-highlight, .ioc-highlight-line');
    for (const el of highlightedLines) {
      el.classList.remove('yara-line-highlight', 'ioc-highlight-line');
    }

    // Remove inline <mark> elements and restore text (both kinds)
    const marks = pc.querySelectorAll('mark.yara-highlight, mark.ioc-highlight');
    for (const mark of marks) {
      const textNode = document.createTextNode(mark.textContent);
      mark.parentNode.replaceChild(textNode, mark);
    }

    // Normalize text nodes (merge adjacent text nodes)
    const codesCells = pc.querySelectorAll('.plaintext-code');
    for (const cell of codesCells) {
      cell.normalize();
    }

    // Renderer-owned CSV YARA highlight — ask the active view to clear its
    // state; its re-render will naturally drop marks and the row-tint class.
    const activeYaraView = this._yaraHighlightActiveView;
    if (activeYaraView && activeYaraView._csvFilters && activeYaraView._csvFilters.clearYaraHighlight) {
      activeYaraView._csvFilters.clearYaraHighlight();
    }
    this._yaraHighlightActiveView = null;

    // Also clear CSV detail pane highlights (legacy DOM sweep — covers stale
    // renderer builds and any residue from other views).
    const csvMarks = pc.querySelectorAll('mark.csv-yara-highlight');
    for (const mark of csvMarks) {
      const textNode = document.createTextNode(mark.textContent);
      mark.parentNode.replaceChild(textNode, mark);
    }
    // Cleanup-gap fix: old code never stripped the row-tint classes, so they
    // could leak between navigations. Strip both IOC and YARA row tints here
    // (IOC is also cleared by _clearIocCsvHighlight; double-strip is safe).
    pc.querySelectorAll('tr.csv-yara-row-highlight, tr.csv-ioc-row-highlight').forEach(tr => {
      tr.classList.remove('csv-yara-row-highlight', 'csv-ioc-row-highlight');
    });
    // Normalize detail value cells
    const detailVals = pc.querySelectorAll('.csv-detail-val');
    for (const cell of detailVals) {
      cell.normalize();
    }
  },

  // Backwards-compatible alias used by CSV highlighter and other callers.
  _clearYaraHighlight() { this._clearMatchHighlight(); },


  // ── Highlight YARA matches in CSV detail pane ──────────────────────────
  //
  // Same contract as _highlightYaraMatchesInline but for the CSV virtualised
  // view. We expand the focus match's row, and after the virtual scroll has
  // rendered, highlight *all* matches that fall within any currently rendered
  // detail pane (typically this is just the focus row's pane plus any other
  // rows the user has already expanded). Matches in off-screen virtualised
  // rows can't be highlighted simultaneously without expanding many rows —
  // cycling through clicks will visit each focus row in turn.
  _highlightYaraMatchesInCsv(csvView, sourceText, matches, focusIdx, forceScroll, ref) {
    // Clear existing YARA highlights + pending timer first.
    this._clearYaraHighlight();

    const filters = csvView._csvFilters;
    if (!filters || !filters.dataRows) return;

    const focusMatch = matches[focusIdx];
    if (!focusMatch) return;

    // Find which row the focus match belongs to.
    let focusRow = null;
    for (const r of filters.dataRows) {
      if (focusMatch.offset >= r.offsetStart && focusMatch.offset < r.offsetEnd) {
        focusRow = r;
        break;
      }
    }
    if (!focusRow) return;

    // Group matches by which CSV row they belong to (by offset range).
    // Attach original matchIdx so we can locate the focus mark.
    const matchesByRowIdx = new Map(); // dataIndex -> [{offset, length, _matchIdx}, ...]
    for (let i = 0; i < matches.length; i++) {
      const m = matches[i];
      if (m.offset == null || !m.length) continue;
      for (const r of filters.dataRows) {
        if (m.offset >= r.offsetStart && m.offset < r.offsetEnd) {
          let arr = matchesByRowIdx.get(r.dataIndex);
          if (!arr) { arr = []; matchesByRowIdx.set(r.dataIndex, arr); }
          arr.push({ offset: m.offset, length: m.length, _matchIdx: i });
          break;
        }
      }
    }

    // Preferred path: renderer owns the highlight lifecycle. createRowElements
    // reapplies .csv-yara-row-highlight + <mark> wrapping on every re-render
    // (scrollend, height remeasure, resize, filter, scroll) until the 5s
    // deadline expires. We just seed the state and drive the scroll.
    //
    // The previous implementation ran a parallel setTimeout here to reset
    // `ref._currentMatchIndex` and tracking fields — but a second timer
    // can desync from the renderer's timer (rapid-click supersession left
    // the sidebar timer outstanding, and when it fired it nulled
    // `_yaraHighlightActiveView` while a later highlight was still live).
    // Delegate to the renderer's `onExpire` callback instead so there is
    // exactly one timer per logical highlight lifetime.
    if (filters.setYaraHighlight && filters.scrollToRow) {
      this._yaraHighlightActiveView = csvView;
      filters.setYaraHighlight(matchesByRowIdx, focusRow.dataIndex, focusIdx, sourceText, 5000, () => {
        if (ref) ref._currentMatchIndex = undefined;
        this._yaraHighlightActiveView = null;
      });
      filters.scrollToRow(focusRow.dataIndex, false).then(() => {
        if (!filters.scrollToYaraFocus) return;
        if (forceScroll) { filters.scrollToYaraFocus(); return; }
        // Otherwise only scroll the focus mark into view if no other mark
        // is currently in the viewport — avoids jarring re-scroll when the
        // user is cycling between visible matches.
        const vh = window.innerHeight || document.documentElement.clientHeight;
        const vw = window.innerWidth || document.documentElement.clientWidth;
        const allMarks = csvView.querySelectorAll('mark.csv-yara-highlight');
        const anyInView = Array.from(allMarks).some(m => {
          const rc = m.getBoundingClientRect();
          return rc.bottom > 0 && rc.top < vh && rc.right > 0 && rc.left < vw && rc.width > 0 && rc.height > 0;
        });
        if (!anyInView) filters.scrollToYaraFocus();
      });
    }
    // The renderer-owned API (setYaraHighlight + scrollToRow) is part of
    // the core _csvFilters contract — every bundled build ships both — so
    // there is no conditional fallback. If the guard above fails, the
    // archive is corrupt or the view was disposed mid-call; either way
    // silently dropping the highlight is the right outcome.
  },


  // ── Update overall risk from encoded content severity ──────────────────
  _updateRiskFromEncodedContent() {
    if (!this.findings || !this.findings.encodedContent) return;
    const riskRank = { critical: 4, high: 3, medium: 2, low: 1 };
    const sevToRisk = { critical: 'critical', high: 'high', medium: 'medium' };
    const currentRank = riskRank[this.findings.risk] || 1;
    let maxRisk = null;
    for (const ef of this.findings.encodedContent) {
      const mapped = sevToRisk[ef.severity];
      if (mapped && (riskRank[mapped] || 0) > (riskRank[maxRisk] || 0)) {
        maxRisk = mapped;
      }
    }
    if (maxRisk && (riskRank[maxRisk] || 0) > currentRank) {
      this.findings.risk = maxRisk;
    }
  },

  // ── Highlight encoded content in the view pane ──────────────────────────
  //
  // `finding._startLine` / `_endLine` are **logical** 1-based line numbers
  // (see `_renderEncodedContentSection`). On minified / single-line files
  // the plaintext renderer soft-wraps one logical line across many <tr>s;
  // translate through `table._lineToFirstRow` so the highlighted range
  // covers every chunk row of the logical span.
  _highlightEncodedInView(finding, flash) {
    this._clearEncodedHighlight();
    const pc = document.getElementById('page-container');
    if (!pc) return;
    const table = pc.querySelector('.plaintext-table');
    if (!table || !finding._startLine) return;

    const rows = table.rows;
    const lineMap = table._lineToFirstRow || null;

    // Translate logical lines → row index range. When no soft-wrap map is
    // present (normal files), this degenerates to the old 1-row-per-line
    // behaviour. End row is "start of next logical line − 1" so all chunk
    // rows of the final logical line are included.
    let start, end;
    if (lineMap) {
      const s = finding._startLine - 1;
      const e = finding._endLine - 1;
      start = (s >= 0 && s < lineMap.length) ? lineMap[s] : (finding._startLine - 1);
      if (e + 1 < lineMap.length) {
        end = lineMap[e + 1] - 1;
      } else {
        end = rows.length - 1;
      }
    } else {
      start = finding._startLine - 1;
      end = finding._endLine - 1;
    }

    for (let i = start; i <= end && i < rows.length; i++) {
      rows[i].classList.add('enc-highlight-line');
      if (flash) rows[i].classList.add('enc-highlight-flash');
    }

    if (flash && start >= 0 && start < rows.length) {
      rows[start].scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    if (flash) {
      setTimeout(() => {
        for (let i = start; i <= end && i < rows.length; i++) {
          rows[i].classList.remove('enc-highlight-flash');
        }
      }, 2000);
    }
  },

  _clearEncodedHighlight() {
    const pc = document.getElementById('page-container');
    if (!pc) return;
    const highlighted = pc.querySelectorAll('.enc-highlight-line');
    for (const el of highlighted) {
      el.classList.remove('enc-highlight-line', 'enc-highlight-flash');
    }
  },

  // ── Flash encoded content card ──────────────────────────────────────────
  _flashEncodedCard(finding) {
    const card = finding._cardEl;
    if (!card) return;
    // Ensure the Encoded Content section is open
    const encDetails = card.closest('.sb-details');
    if (encDetails && !encDetails.open) encDetails.open = true;
    card.classList.remove('enc-card-flash');
    void card.offsetWidth; // force reflow to restart animation
    card.classList.add('enc-card-flash');
    card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    setTimeout(() => card.classList.remove('enc-card-flash'), 1500);
  },

  // ── Flash IOC rows linked to an encoded finding ─────────────────────────
  _flashIocRows(finding) {
    const rows = finding._iocRows;
    if (!rows || !rows.length) return;
    // Ensure parent section is open
    const sigDetails = rows[0].closest('.sb-details');
    if (sigDetails && !sigDetails.open) sigDetails.open = true;
    // Small delay to let section expand before scrolling
    setTimeout(() => {
      for (const tr of rows) {
        tr.classList.remove('ioc-encoded-flash');
        void tr.offsetWidth;
        tr.classList.add('ioc-encoded-flash');
      }
      rows[0].scrollIntoView({ behavior: 'smooth', block: 'center' });
      setTimeout(() => { for (const tr of rows) tr.classList.remove('ioc-encoded-flash'); }, 1500);
    }, 50);
  },

  // ── IOC subtle-highlight inside CSV expanded row ────────────────────────
  //
  // Complements _highlightYaraMatchesInCsv. The renderer owns the highlight
  // lifecycle — we just tell it which row + term and schedule the
  // ref._currentMatchIndex reset. The renderer's createRowElements re-applies
  // the .csv-ioc-row-highlight class and wraps <mark> tags on every re-render
  // (scrollend, height remeasure, resize, etc.) until the deadline expires,
  // which is what makes the highlight stable through the post-scroll DOM
  // churn that previously wiped it.
  _highlightIocInCsvRow(csvView, searchTerm, dataIdx, ref) {
    this._clearIocCsvHighlight();
    const filters = csvView && csvView._csvFilters;
    if (!filters || !searchTerm) return;

    // Renderer-owned highlight. The renderer's `onExpire` callback is
    // invoked when (and only when) its own timer fires and this
    // highlight hasn't been superseded — rapid clicks replace the
    // renderer's timer and the old timer's `onExpire` never runs.
    //
    // `scrollToRowWithIocHighlight` is part of the core _csvFilters
    // contract — every bundled build ships it — so there is no
    // conditional fallback. If the guard below fails, the view was
    // disposed mid-call; silently dropping the highlight is correct.
    if (filters.scrollToRowWithIocHighlight) {
      this._iocCsvHighlightActiveView = csvView;
      filters.scrollToRowWithIocHighlight(dataIdx, searchTerm, 5000, () => {
        if (ref) ref._currentMatchIndex = undefined;
        this._iocCsvHighlightActiveView = null;
      });
    }
  },

  _clearIocCsvHighlight() {
    // Renderer-owned path: ask the active CSV view to clear its state.
    const activeView = this._iocCsvHighlightActiveView;
    if (activeView && activeView._csvFilters && activeView._csvFilters.clearIocHighlight) {
      activeView._csvFilters.clearIocHighlight();
    }
    this._iocCsvHighlightActiveView = null;

    // Defensive DOM sweep — covers residue from prior pages where a CSV
    // view got detached before its renderer's clearIocHighlight could
    // fire. The renderer-owned path also tears down on re-render, so
    // double-removal here is safe.
    document.querySelectorAll('mark.csv-ioc-highlight').forEach(m => {
      const parent = m.parentNode;
      if (!parent) return;
      while (m.firstChild) parent.insertBefore(m.firstChild, m);
      parent.removeChild(m);
      parent.normalize();
    });
    document.querySelectorAll('tr.csv-ioc-row-highlight').forEach(tr => {
      tr.classList.remove('csv-ioc-row-highlight');
    });
  },

  // ── IOC subtle-highlight inside EVTX expanded detail panes ──────────────
  //
  // After filters+expandAll renders the relevant rows, walk every visible
  // detail pane and wrap the first occurrence of `searchTerm` (per text node)
  // in a subtle yellow <mark>. Auto-clears after 5 seconds.
  _highlightIocInEvtxRows(evtxView, searchTerm, ref) {
    this._clearIocEvtxHighlight();
    if (!searchTerm || !evtxView) return;
    const termLower = searchTerm.toLowerCase();

    requestAnimationFrame(() => {
      const panes = evtxView.querySelectorAll('.evtx-detail-pane, .evtx-record-readable');
      let firstMark = null;
      for (const pane of panes) {
        const walker = document.createTreeWalker(pane, NodeFilter.SHOW_TEXT, null);
        const nodes = [];
        let n;
        while ((n = walker.nextNode())) {
          // Skip text already inside a <mark> (defensive)
          if (n.parentNode && n.parentNode.tagName === 'MARK') continue;
          nodes.push(n);
        }
        for (const tn of nodes) {
          const text = tn.nodeValue;
          const idx = text.toLowerCase().indexOf(termLower);
          if (idx === -1) continue;
          // Split and wrap (work on tail → mid so offsets stay valid)
          tn.splitText(idx + searchTerm.length);
          const mid = tn.splitText(idx);
          const mark = document.createElement('mark');
          mark.className = 'evtx-ioc-highlight evtx-ioc-highlight-flash';
          mid.parentNode.insertBefore(mark, mid);
          mark.appendChild(mid);
          if (!firstMark) firstMark = mark;
        }
      }
      if (firstMark) firstMark.scrollIntoView({ behavior: 'smooth', block: 'center' });

      this._iocEvtxHighlightTimer = setTimeout(() => {
        this._clearIocEvtxHighlight();
        if (ref) ref._currentMatchIndex = undefined;
        this._iocEvtxHighlightTimer = null;
      }, 5000);
    });
  },

  _clearIocEvtxHighlight() {
    if (this._iocEvtxHighlightTimer) {
      clearTimeout(this._iocEvtxHighlightTimer);
      this._iocEvtxHighlightTimer = null;
    }
    document.querySelectorAll('mark.evtx-ioc-highlight').forEach(m => {
      const parent = m.parentNode;
      if (!parent) return;
      while (m.firstChild) parent.insertBefore(m.firstChild, m);
      parent.removeChild(m);
      parent.normalize();
    });
  },

  // ── Apply "return focus" to a Deobfuscation card after drill-down ───────
  //
  // Invoked from `_renderSidebar` (inside a rAF) when the nav frame we're
  // restoring was tagged with `returnFocus = { section:'deobfuscation',
  // findingOffset: N }` by one of the Deobfuscation drill-down buttons.
  //
  // Locates the card by the `data-enc-offset` attribute we stamp when
  // rendering each `.enc-finding-card`, force-opens its containing
  // <details>, scrolls the `#sb-body` pane so the card is centred in view,
  // and flashes the card (reusing the existing `.enc-card-flash` keyframes)
  // so the analyst can immediately see where they came from and move on
  // to the next finding without hunting.
  //
  // Uses `block: 'nearest'` to avoid yanking the whole viewport when the
  // card is already partially visible; the flash provides the visual cue.
  _applyDeobfuscationReturnFocus(returnFocus) {
    // Clear the transient force-open flag now that the section is rendered.
    this._forceDeobfuscationOpen = false;

    if (!returnFocus || returnFocus.findingOffset === undefined ||
        returnFocus.findingOffset === null) return;

    const sbBody = document.getElementById('sb-body');
    if (!sbBody) return;

    // Locate the card by the stamped data-enc-offset attribute. CSS
    // attribute-selector escaping would be needed for truly arbitrary
    // values, but finding.offset is always a non-negative integer.
    const offsetStr = String(returnFocus.findingOffset);
    const card = sbBody.querySelector(
      `.enc-finding-card[data-enc-offset="${offsetStr}"]`);
    if (!card) return;

    // Ensure its owning <details> is open (belt-and-braces — the force-open
    // branch above already did this, but a stale override could still flip
    // the section closed).
    const sect = card.closest('.sb-details');
    if (sect && !sect.open) sect.open = true;

    // Flash the card (restart the animation by toggling the class).
    card.classList.remove('enc-card-flash');
    void card.offsetWidth;
    card.classList.add('enc-card-flash');
    setTimeout(() => card.classList.remove('enc-card-flash'), 1500);

    // Scroll the card into view inside the sidebar pane. We deliberately
    // use 'nearest' instead of 'center' so the viewer pane isn't jolted
    // when the sidebar is the target container.
    card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  },

  // ── Get deepest decoded finding in innerFindings tree ───────────────────
  _getDeepestFinding(finding, _depth) {
    if (_depth === undefined) _depth = 0;
    if (_depth > 20) return finding; // safety cap — prevent infinite recursion on cyclic graphs
    if (!finding.innerFindings || !finding.innerFindings.length) return finding;
    const sevRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const best = finding.innerFindings.reduce((a, b) =>
      (sevRank[b.severity] ?? 0) > (sevRank[a.severity] ?? 0) ? b : a
    );
    if (best.decodedBytes || best.rawCandidate || (best.innerFindings && best.innerFindings.length)) {
      return this._getDeepestFinding(best, _depth + 1);
    }
    return (best.decodedBytes || best.rawCandidate) ? best : finding;
  },

  // ── Binary Metadata section (PE / ELF / Mach-O only) ──────────────────────
  //
  // Mirrors the Tier-A verdict band rendered above the Binary Pivot card in
  // the main viewer, distilled to a copy-friendly sidebar snapshot. This is
  // deliberately complementary — not a duplicate — of the main-pane card:
  // we surface the headline verdict one-liner, the risk score, the short
  // badge row, and the handful of pivot fields analysts most often paste
  // into a ticket (signer, compile-ts-faked flag, EP anomaly, overlay,
  // packer, and the format-specific identity row from
  // `findings.metadata`). The deep structural detail (section tables,
  // resource walks, dylibs, etc.) stays in the main viewer's Tier-C cards.
  //
  // Stash contract: `this._binaryParsed` and `this._binaryFormat` are
  // populated by `app-load.js::pe() / elf() / macho()` dispatchers after
  // the renderer returns; `_clearFile()` nulls them both on file close.
  // If either is missing we quietly bail — the guard in `_renderSidebar`
  // already skips this path for non-binary formats, but the internal
  // guard keeps the method safe against a mid-render state flip.
  //
  // Docs: see CONTRIBUTING.md → "Binary triage surfaces" for the module
  // family (`mitre.js`, `binary-verdict.js`, `binary-anomalies.js`,
  // `binary-triage.js`) and the renderer-contract notes that keep
  // the stash in sync with each Tier-A band.
  _renderBinaryMetadataSection(container, fileName) {
    if (!this._binaryFormat || !this._binaryParsed) return;
    if (typeof BinaryVerdict === 'undefined') return;

    const f = this.findings || {};
    const fileSize = (this._fileMeta && this._fileMeta.size) ||
      (this._fileBuffer && this._fileBuffer.byteLength) || 0;

    let verdict;
    try {
      verdict = BinaryVerdict.summarize({
        parsed: this._binaryParsed,
        findings: f,
        format: this._binaryFormat === 'pe' ? 'PE'
              : this._binaryFormat === 'elf' ? 'ELF'
              : 'Mach-O',
        fileSize,
      });
    } catch (_) {
      return;
    }
    if (!verdict) return;

    const det = document.createElement('details');
    det.className = 'sb-details';
    det.dataset.sbSection = 'binaryMeta';
    // Open by default on medium+ tiers; collapsed on low / clean samples
    // so the sidebar stays compact when nothing interesting is flagged.
    const defaultOpen = verdict.tier === 'critical' ||
      verdict.tier === 'high' || verdict.tier === 'medium';
    det.open = this._resolveSectionOpen('binaryMeta', defaultOpen);

    const sum = document.createElement('summary');
    sum.className = 'sb-details-summary';
    const fmtLabel = this._binaryFormat === 'pe' ? 'PE'
      : this._binaryFormat === 'elf' ? 'ELF'
      : 'Mach-O';
    sum.textContent = `🧬 Binary Triage — ${fmtLabel} (${verdict.risk})`;
    det.appendChild(sum);

    const body = document.createElement('div');
    body.className = 'sb-details-body';

    // ── Verdict one-liner + tier / risk pill ────────────────────────────
    const tierMap = {
      critical: { label: 'Critical',    badge: 'critical' },
      high:     { label: 'High risk',   badge: 'high'     },
      medium:   { label: 'Medium risk', badge: 'medium'   },
      low:      { label: 'Low risk',    badge: 'info'     },
      clean:    { label: 'Clean',       badge: 'info'     },
    };
    const tierInfo = tierMap[verdict.tier] || tierMap.clean;

    const tierRow = document.createElement('div');
    tierRow.className = 'sb-bin-tier-row';
    tierRow.style.cssText = 'display:flex;align-items:center;gap:8px;margin:4px 0 8px;';
    const tierBadge = document.createElement('span');
    tierBadge.className = `badge badge-${tierInfo.badge}`;
    tierBadge.textContent = tierInfo.label;
    tierRow.appendChild(tierBadge);
    const riskNum = document.createElement('span');
    riskNum.style.cssText = 'font-size:11px;color:#666;';
    riskNum.textContent = `risk ${verdict.risk}/100`;
    tierRow.appendChild(riskNum);
    body.appendChild(tierRow);

    if (verdict.headline) {
      const head = document.createElement('div');
      head.className = 'sb-bin-headline';
      head.style.cssText = 'font-size:11px;line-height:1.45;margin:2px 0 10px;color:#333;';
      head.textContent = verdict.headline;
      body.appendChild(head);
    }

    // Badge row (compact) — reuse verdict.badges from BinaryVerdict.
    if (Array.isArray(verdict.badges) && verdict.badges.length) {
      const badgeRow = document.createElement('div');
      badgeRow.style.cssText = 'display:flex;flex-wrap:wrap;gap:4px;margin:0 0 10px;';
      for (const b of verdict.badges) {
        const sevMap = { bad: 'high', warn: 'medium', ok: 'info', info: 'info' };
        const cls = 'badge-' + (sevMap[b.kind] || 'info');
        const span = document.createElement('span');
        span.className = 'badge ' + cls;
        span.textContent = b.label || '';
        badgeRow.appendChild(span);
      }
      body.appendChild(badgeRow);
    }

    // ── Pivot fields table ──────────────────────────────────────────────
    // Minimal meta-table of the rows an analyst copy-pastes into a
    // ticket / Slack thread. The full structured card lives in the main
    // viewer; this is the paste-friendly subset keyed off findings.metadata
    // (populated consistently across all three binary renderers).
    const md = f.metadata || {};
    const rows = [];

    // Signer
    if (verdict.signer) rows.push(['Signer', verdict.signer]);

    // Format-specific identity row
    if (this._binaryFormat === 'pe') {
      if (md['CLR Runtime'])       rows.push(['CLR Runtime',  md['CLR Runtime']]);
      if (md['Installer'])         rows.push(['Installer',    md['Installer']]);
    } else if (this._binaryFormat === 'elf') {
      if (md['Build ID'])          rows.push(['Build ID',     md['Build ID']]);
      if (md['SONAME'])            rows.push(['SONAME',       md['SONAME']]);
      if (md['Interpreter'])       rows.push(['Interpreter',  md['Interpreter']]);
      if (md['Linking'])           rows.push(['Linking',      md['Linking']]);
    } else if (this._binaryFormat === 'macho') {
      const csi = (this._binaryParsed.codeSignatureInfo) || {};
      if (csi.teamId)              rows.push(['Team ID',      csi.teamId]);
      if (md['Bundle ID'])         rows.push(['Bundle ID',    md['Bundle ID']]);
      if (md['Platform'])          rows.push(['Platform',     md['Platform']]);
      if (md['UUID'])              rows.push(['UUID',         md['UUID']]);
    }

    // Hash pivots (import / rich / sym)
    if (md['Imphash'])                 rows.push(['Imphash',      md['Imphash']]);
    if (md['Import Hash (MD5)'])       rows.push(['Import Hash',  md['Import Hash (MD5)']]);
    if (md['RichHash'])                rows.push(['RichHash',     md['RichHash']]);
    if (md['SymHash'])                 rows.push(['SymHash',      md['SymHash']]);

    // Compile-timestamp faked flag
    if (md['Compile Timestamp Faked']) rows.push(['Timestamp',  '⚠ ' + md['Compile Timestamp Faked']]);

    // TLS callbacks
    if (md['TLS Callbacks'])           rows.push(['TLS Callbacks', md['TLS Callbacks']]);

    // Overlay + packer signals
    if (md['Overlay Size'])            rows.push(['Overlay',      md['Overlay Size'] + (md['Overlay Type'] ? ' · ' + md['Overlay Type'] : '')]);
    if (md['Overlay Entropy'])         rows.push(['Overlay H',    md['Overlay Entropy']]);
    if (md['DLL Side-Load Host'])      rows.push(['Side-Load',    '⚠ export set matches known host-DLL']);
    if (md['Forwarded Exports'])       rows.push(['Forwarded',    md['Forwarded Exports']]);

    if (rows.length) {
      body.appendChild(this._sec('Pivot Fields'));
      const tbl = document.createElement('table'); tbl.className = 'meta-table';
      for (const [k, v] of rows) {
        const tr = document.createElement('tr');
        const td1 = document.createElement('td'); td1.textContent = k;
        const td2 = document.createElement('td');
        td2.textContent = String(v);
        // Copy button for identifiers that are paste targets.
        if (/^(Team ID|Imphash|Import Hash|RichHash|SymHash|Build ID|Bundle ID|UUID|SONAME)$/.test(k)) {
          const cb = document.createElement('button');
          cb.className = 'copy-url-btn';
          cb.textContent = '📋';
          cb.title = 'Copy';
          cb.style.marginLeft = '4px';
          cb.addEventListener('click', (e) => {
            e.stopPropagation();
            this._copyToClipboard(String(v));
          });
          td2.appendChild(cb);
        }
        tr.appendChild(td1); tr.appendChild(td2); tbl.appendChild(tr);
      }
      body.appendChild(tbl);
    }

    // ── Anomaly ribbon (compact) ────────────────────────────────────────
    // Mirrors the main viewer's chip row — mainly useful when the user has
    // the sidebar open but is scrolled past the Tier-A band. Falls back to
    // nothing when no anomalies fire.
    if (typeof BinaryAnomalies !== 'undefined') {
      try {
        const a = BinaryAnomalies.detect({
          parsed: this._binaryParsed,
          findings: f,
          format: fmtLabel,
        });
        if (a && Array.isArray(a.ribbon) && a.ribbon.length) {
          body.appendChild(this._sec('Anomalies'));
          const row = document.createElement('div');
          row.style.cssText = 'display:flex;flex-wrap:wrap;gap:4px;margin-top:4px;';
          for (const chip of a.ribbon) {
            const sp = document.createElement('span');
            const sevBadge = chip.severity === 'critical' ? 'critical'
              : chip.severity === 'high' ? 'high'
              : chip.severity === 'medium' ? 'medium'
              : 'info';
            sp.className = 'badge badge-' + sevBadge;
            sp.textContent = chip.label;
            if (chip.mitre && typeof MITRE !== 'undefined') {
              const info = MITRE.lookup(chip.mitre);
              sp.title = info ? (chip.mitre + ' — ' + info.name) : chip.mitre;
            }
            row.appendChild(sp);
          }
          body.appendChild(row);
        }
      } catch (_) { /* best-effort */ }
    }

    det.appendChild(body);
    container.appendChild(det);
  },

  // ── MITRE ATT&CK Coverage section (PE / ELF / Mach-O only) ────────────────
  //
  // Rolls every `[Tnnnn.nnn]` token emitted by a capability / anomaly /
  // overlay / side-load finding into a tactic-grouped card. Keeps the
  // sidebar focused on the *coverage* view (what kill-chain stages are
  // represented in this sample) rather than the evidence strings, which
  // already live in the Detections section directly above.
  //
  // The rollup is driven entirely by `findings.externalRefs[type='pattern']`
  // — the canonical emission channel used by `Capabilities.detect()`,
  // entry-point anomaly checks, TLS-callback warnings, overlay flags,
  // side-load hosts, etc. — so any new emission that tags itself with a
  // MITRE id will automatically surface here without further wiring.
  _renderMitreSection(container, fileName) {
    if (!this._binaryFormat) return;
    if (typeof MITRE === 'undefined') return;

    const f = this.findings || {};
    const refs = Array.isArray(f.externalRefs) ? f.externalRefs : [];

    // Walk every IOC.PATTERN row and pull out any `[Tnnnn.nnn]` tokens
    // embedded in its name/value. Severity is inherited from the ref so
    // the rollup can colour-code and order accordingly. The same
    // technique can appear across multiple refs (e.g. Process Injection
    // hits from CreateRemoteThread and VirtualAllocEx both map to T1055) —
    // `MITRE.rollupByTactic` dedups within a tactic and keeps the
    // highest-severity evidence line.
    const items = [];
    const RX = /\[(T\d{4}(?:\.\d{3})?)\]/g;
    for (const r of refs) {
      if (!r) continue;
      const type = (r.type || '').toLowerCase();
      if (type !== 'pattern') continue;
      const name = r.name || r.value || r.url || '';
      let m;
      RX.lastIndex = 0;
      while ((m = RX.exec(name)) !== null) {
        items.push({ id: m[1], evidence: name, severity: r.severity || 'medium' });
      }
    }
    if (!items.length) return;

    const rollup = MITRE.rollupByTactic(items);
    if (!rollup.length) return;

    const det = document.createElement('details');
    det.className = 'sb-details';
    det.dataset.sbSection = 'mitreCoverage';
    // Auto-open when the top tactic has a meaningful cluster (≥ 3
    // techniques) or any critical-severity technique is present.
    // Otherwise stay collapsed so the card is available-but-quiet.
    const top = rollup[0];
    const hasCritical = rollup.some(t => t.techniques.some(x => x.severity === 'critical'));
    const defaultOpen = (top && top.techniques.length >= 3) || hasCritical;
    det.open = this._resolveSectionOpen('mitreCoverage', defaultOpen);

    const totalTechs = rollup.reduce((s, t) => s + t.techniques.length, 0);
    const sum = document.createElement('summary');
    sum.className = 'sb-details-summary';
    sum.textContent = `🎯 MITRE ATT&CK Coverage (${totalTechs})`;
    det.appendChild(sum);

    const body = document.createElement('div');
    body.className = 'sb-details-body';

    for (const t of rollup) {
      body.appendChild(this._sec(`${t.tacticIcon || '•'} ${t.tacticLabel} — ${t.techniques.length}`));
      const tbl = document.createElement('table');
      tbl.className = 'meta-table';
      for (const tech of t.techniques) {
        const tr = document.createElement('tr');

        const td1 = document.createElement('td');
        const a = document.createElement('a');
        a.href = tech.url;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        a.textContent = tech.id;
        a.title = 'Open on attack.mitre.org';
        a.style.cssText = 'color:#1a73e8;text-decoration:none;font-weight:600;';
        td1.appendChild(a);

        const td2 = document.createElement('td');
        const nm = document.createElement('span');
        nm.textContent = tech.name;
        td2.appendChild(nm);
        if (tech.severity && tech.severity !== 'info') {
          const b = document.createElement('span');
          const sevClass = tech.severity === 'critical' ? 'critical'
            : tech.severity === 'high' ? 'high'
            : tech.severity === 'medium' ? 'medium'
            : 'info';
          b.className = 'badge badge-' + sevClass;
          b.textContent = tech.severity;
          b.style.marginLeft = '6px';
          td2.appendChild(b);
        }

        tr.appendChild(td1); tr.appendChild(td2);
        tbl.appendChild(tr);
      }
      body.appendChild(tbl);
    }

    det.appendChild(body);
    container.appendChild(det);
  },
});
