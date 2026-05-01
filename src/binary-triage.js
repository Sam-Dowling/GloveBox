// binary-triage.js — Tier-A "verdict band" renderer for PE / ELF / Mach-O.
//
// Glues together BinaryVerdict.summarize (one-liner + risk 0-100),
// BinaryAnomalies.detect (coloured chip ribbon), and MITRE.rollupByTactic
// (tactic-grouped capability strip) into a single DOM node that renders
// above the Binary Pivot card in each of the three native-binary
// renderers. Triage-first by construction: an analyst sees the verdict
// sentence, the ribbon of things-that-went-wrong, and the MITRE rollup
// before any structural tables.
//
// Pure presentation — reads `parsed` / `findings` only.
//
// Contract
// --------
//   BinaryTriage.render({ parsed, findings, format, fileSize }) → HTMLElement
//
// The returned element already has the `bin-triage` class and is ready
// to append. The helper also exposes `BinaryTriage.shouldOpen(cardId)`
// via a closure the renderer can call when deciding whether a given
// Tier-C card should start open.

(function () {
  'use strict';

  const _esc = escHtml;

  function _tierLabel(tier) {
    switch (tier) {
      case 'critical': return 'Critical';
      case 'high':     return 'High risk';
      case 'medium':   return 'Medium risk';
      case 'low':      return 'Low risk';
      case 'clean':    return 'No obvious threat';
      default:         return 'Unknown';
    }
  }

  function _renderVerdictBand(verdict) {
    const band = document.createElement('div');
    band.className = 'bin-triage-verdict bin-triage-tier-' + (verdict.tier || 'clean');

    // Left: risk gauge (coarse bar with numeric).
    const gauge = document.createElement('div');
    gauge.className = 'bin-triage-gauge';
    gauge.innerHTML =
      '<div class="bin-triage-risk-num">' + Math.round(verdict.risk || 0) + '</div>' +
      '<div class="bin-triage-risk-label">risk</div>';
    band.appendChild(gauge);

    // Right: tier + headline one-liner.
    const textWrap = document.createElement('div');
    textWrap.className = 'bin-triage-text';
    const tierEl = document.createElement('div');
    tierEl.className = 'bin-triage-tier';
    tierEl.textContent = _tierLabel(verdict.tier || 'clean');
    const headline = document.createElement('div');
    headline.className = 'bin-triage-headline';
    headline.textContent = verdict.headline || '';
    textWrap.appendChild(tierEl);
    textWrap.appendChild(headline);

    // Badges row.
    if (Array.isArray(verdict.badges) && verdict.badges.length) {
      const badgeRow = document.createElement('div');
      badgeRow.className = 'bin-triage-badges';
      for (const b of verdict.badges) {
        const span = document.createElement('span');
        span.className = 'bin-triage-badge bin-triage-badge-' + (b.kind || 'info');
        span.textContent = b.label || '';
        badgeRow.appendChild(span);
      }
      textWrap.appendChild(badgeRow);
    }

    // "Why this risk?" reasons panel — explains the gauge so analysts
    // don't have to reverse-engineer where the score came from. Mirrors
    // the panel rendered under the sidebar risk banner so both surfaces
    // tell the same story.
    const reasonsEl = renderReasonsPanel(verdict.reasons, verdict.rawScore, verdict.risk);
    if (reasonsEl) textWrap.appendChild(reasonsEl);

    band.appendChild(textWrap);
    return band;
  }

  // Render the shared "Why this risk?" expandable panel. Returns null when
  // there are no reasons to show (preserves the clean low-risk look).
  // Used both here (verdict band) and from the sidebar — see
  // `app-sidebar.js → _renderRiskReasons`.
  function renderReasonsPanel(reasons, rawScore, gaugeRisk) {
    if (!Array.isArray(reasons) || !reasons.length) return null;
    const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const sorted = reasons.slice().sort((a, b) => {
      const da = typeof a.delta === 'number' ? a.delta : 0;
      const db = typeof b.delta === 'number' ? b.delta : 0;
      if (db !== da) return db - da;
      return (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0);
    });

    const det = document.createElement('details');
    det.className = 'bin-triage-why';

    const sum = document.createElement('summary');
    sum.className = 'bin-triage-why-summary';
    const totalDelta = sorted.reduce((s, r) => s + (typeof r.delta === 'number' ? r.delta : 0), 0);
    sum.textContent = `Why this risk? (${sorted.length} reason${sorted.length === 1 ? '' : 's'}, +${totalDelta.toFixed(1)} score)`;
    det.appendChild(sum);

    const tbl = document.createElement('table');
    tbl.className = 'bin-triage-why-tbl';
    const tbody = document.createElement('tbody');
    for (const r of sorted) {
      const tr = document.createElement('tr');
      tr.className = 'bin-triage-why-row sev-' + (r.severity || 'info');

      const sevTd = document.createElement('td');
      sevTd.className = 'bin-triage-why-sev';
      const dot = document.createElement('span');
      dot.className = 'sev-dot sev-dot-' + (r.severity || 'info');
      dot.setAttribute('aria-hidden', 'true');
      sevTd.appendChild(dot);
      tr.appendChild(sevTd);

      const labelTd = document.createElement('td');
      labelTd.className = 'bin-triage-why-label';
      labelTd.textContent = r.label || '';
      tr.appendChild(labelTd);

      const deltaTd = document.createElement('td');
      deltaTd.className = 'bin-triage-why-delta';
      const d = typeof r.delta === 'number' ? r.delta : 0;
      deltaTd.textContent = d > 0 ? '+' + d.toFixed(1) : d.toFixed(1);
      tr.appendChild(deltaTd);

      const catTd = document.createElement('td');
      catTd.className = 'bin-triage-why-cat';
      catTd.textContent = r.category || '';
      tr.appendChild(catTd);

      tbody.appendChild(tr);
    }
    tbl.appendChild(tbody);
    det.appendChild(tbl);

    // Footer: relate the additive score to the displayed gauge so the
    // mapping is explicit (verdict band shows 0-100; renderer score is
    // additive, the gauge multiplies by 6 then clamps and adds structural
    // augments). Only show the gauge mapping when a numeric `gaugeRisk`
    // was passed — the sidebar passes null because it shows a coarse tier
    // rather than a 0-100 gauge.
    if (typeof rawScore === 'number' && rawScore > 0) {
      const ft = document.createElement('div');
      ft.className = 'bin-triage-why-foot';
      ft.textContent = (typeof gaugeRisk === 'number')
        ? `Score ${rawScore.toFixed(1)} → gauge ${Math.round(gaugeRisk || 0)} / 100`
        : `Total score: ${rawScore.toFixed(1)}`;
      det.appendChild(ft);
    }

    return det;
  }

  function _renderRibbon(anomalies) {
    if (!anomalies || !Array.isArray(anomalies.ribbon) || !anomalies.ribbon.length) return null;
    const row = document.createElement('div');
    row.className = 'bin-triage-ribbon';
    const label = document.createElement('span');
    label.className = 'bin-triage-ribbon-label';
    label.textContent = '⚠ Anomalies:';
    row.appendChild(label);
    for (const chip of anomalies.ribbon) {
      const c = document.createElement('span');
      c.className = 'bin-triage-chip bin-triage-chip-' + (chip.severity || 'medium');
      c.textContent = chip.label;
      if (chip.mitre && typeof MITRE !== 'undefined') {
        const info = MITRE.lookup(chip.mitre);
        if (info) c.title = chip.mitre + ' — ' + info.name;
      }
      row.appendChild(c);
    }
    return row;
  }

  function _renderMitreStrip(findings) {
    if (typeof MITRE === 'undefined') return null;
    const refs = (findings && findings.externalRefs) || [];
    // Every capability row carries a `[Tnnnn.nnn]` suffix in its name. Pull
    // those out to drive the rollup.
    const items = [];
    const RX = /\[(T\d{4}(?:\.\d{3})?)\]/g;
    for (const r of refs) {
      if (!r) continue;
      const type = (r.type || '').toLowerCase();
      if (type !== 'pattern') continue;
      const name = r.name || r.value || '';
      let m;
      RX.lastIndex = 0;
      while ((m = RX.exec(name)) !== null) {
        items.push({ id: m[1], evidence: name, severity: r.severity || 'medium' });
      }
    }
    if (!items.length) return null;

    const rollup = MITRE.rollupByTactic(items);
    if (!rollup.length) return null;

    const strip = document.createElement('div');
    strip.className = 'bin-triage-mitre';
    const title = document.createElement('div');
    title.className = 'bin-triage-mitre-title';
    title.textContent = '🎯 MITRE ATT&CK Coverage';
    strip.appendChild(title);

    const tactics = document.createElement('div');
    tactics.className = 'bin-triage-mitre-tactics';
    for (const t of rollup) {
      const col = document.createElement('div');
      col.className = 'bin-triage-tactic';
      const hdr = document.createElement('div');
      hdr.className = 'bin-triage-tactic-hdr';
      hdr.innerHTML = '<span class="bin-triage-tactic-icon">' + _esc(t.tacticIcon) + '</span> ' +
        '<span class="bin-triage-tactic-label">' + _esc(t.tacticLabel) + '</span> ' +
        '<span class="bin-triage-tactic-count">' + t.techniques.length + '</span>';
      col.appendChild(hdr);
      for (const tech of t.techniques) {
        const row = document.createElement('div');
        row.className = 'bin-triage-tech bin-triage-tech-' + (tech.severity || 'medium');
        const a = document.createElement(tech.url ? 'a' : 'span');
        a.className = 'bin-triage-tech-id';
        if (tech.url) {
          a.href = tech.url;
          a.target = '_blank';
          a.rel = 'noopener noreferrer';
        }
        a.textContent = tech.id;
        row.appendChild(a);
        const nm = document.createElement('span');
        nm.className = 'bin-triage-tech-name';
        nm.textContent = ' ' + tech.name;
        row.appendChild(nm);
        col.appendChild(row);
      }
      tactics.appendChild(col);
    }
    strip.appendChild(tactics);
    return strip;
  }

  // ── Public API ───────────────────────────────────────────────────────────
  function render(opts) {
    const parsed = (opts && opts.parsed) || {};
    const findings = (opts && opts.findings) || {};
    const format = (opts && opts.format) || '';
    const fileSize = (opts && opts.fileSize) || 0;

    const wrap = document.createElement('section');
    wrap.className = 'bin-triage';

    // 1) Verdict band
    let verdict = null;
    try {
      if (typeof BinaryVerdict !== 'undefined') {
        verdict = BinaryVerdict.summarize({ parsed, findings, format, fileSize });
        wrap.appendChild(_renderVerdictBand(verdict));
      }
    } catch (_) { /* best-effort */ }

    // 2) Anomaly ribbon
    let anomalies = null;
    try {
      if (typeof BinaryAnomalies !== 'undefined') {
        anomalies = BinaryAnomalies.detect({ parsed, findings, format });
        const ribbon = _renderRibbon(anomalies);
        if (ribbon) wrap.appendChild(ribbon);
      }
    } catch (_) { /* best-effort */ }

    // 3) MITRE tactic-grouped strip
    try {
      const strip = _renderMitreStrip(findings);
      if (strip) wrap.appendChild(strip);
    } catch (_) { /* best-effort */ }

    return wrap;
  }

  // Expose a helper to ask "should card X auto-open?" independent of the
  // render() call so renderers can query without needing the verdict object.
  function shouldAutoOpen(opts, cardId) {
    try {
      if (typeof BinaryAnomalies === 'undefined') return false;
      const a = BinaryAnomalies.detect({ parsed: opts.parsed, findings: opts.findings, format: opts.format });
      return !!(a && a.shouldAutoOpen && a.shouldAutoOpen.get(cardId));
    } catch (_) {
      return false;
    }
  }

  window.BinaryTriage = {
    render,
    shouldAutoOpen,
    renderReasonsPanel,
  };
})();
