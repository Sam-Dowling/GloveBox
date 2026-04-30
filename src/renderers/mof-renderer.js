'use strict';
// ════════════════════════════════════════════════════════════════════════════
// mof-renderer.js — Managed Object Format (.mof) WMI schema analysis.
//
// MOF is the textual schema language for WMI (Windows Management
// Instrumentation). Compiled by `mofcomp.exe` into the WMI repository.
// Legitimate uses include hardware drivers and Windows feature schemas;
// malicious uses centre on **WMI Event Subscription** persistence
// (ATT&CK T1546.003).
//
// The persistence triad is:
//   __EventFilter                  — query that matches a system event
//   ActiveScriptEventConsumer /    — VBScript/JScript reaction
//   CommandLineEventConsumer /     — process spawn reaction (HIGH)
//   __FilterToConsumerBinding      — wires filter → consumer
//
// Stuxnet, MoonBounce, Black Energy, and many APT toolkits all use this
// combination. The renderer extracts every ScriptText / CommandLineTemplate
// / Query value and surfaces them with click-to-focus offsets, plus
// fires high-severity Pattern detections for the canonical triad.
//
// Detection scope:
//   • CommandLineEventConsumer.CommandLineTemplate → critical (T1546.003 + arbitrary-cmd)
//   • ActiveScriptEventConsumer.ScriptText → high (T1546.003)
//   • __FilterToConsumerBinding present → high (the triad is wired up)
//   • #pragma include(remote URL) → high (remote MOF inclusion)
//   • Any __EventFilter / EventConsumer reference → medium banner
//
// Depends on: constants.js (IOC, escHtml, escalateRisk, lfNormalize, pushIOC)
// ════════════════════════════════════════════════════════════════════════════
class MofRenderer {

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const wrap = document.createElement('div');
    wrap.className = 'mof-view';

    const banner = document.createElement('div');
    banner.className = 'doc-extraction-banner';
    const strong = document.createElement('strong');
    strong.textContent = '⚠ Managed Object Format (.mof)';
    banner.appendChild(strong);
    banner.appendChild(document.createTextNode(
      ' — WMI schema language. Compiled by mofcomp.exe into the WMI repository. ' +
      'Often abused for persistent WMI Event Subscriptions (ATT&CK T1546.003).'
    ));
    wrap.appendChild(banner);

    const summary = MofRenderer._summarize(text);
    const info = document.createElement('div');
    info.className = 'plaintext-info';
    info.textContent = `${summary.classes.length} class instance(s)  ·  ${summary.bindings} binding(s)  ·  ${this._fmtBytes(bytes.length)}  ·  MOF file`;
    wrap.appendChild(info);

    if (summary.classes.length) {
      const card = document.createElement('div');
      card.className = 'mof-card';
      const h = document.createElement('h4');
      h.textContent = 'Class instances';
      card.appendChild(h);
      const ul = document.createElement('ul');
      for (const c of summary.classes) {
        const li = document.createElement('li');
        const code = document.createElement('code');
        code.textContent = c;
        li.appendChild(code);
        ul.appendChild(li);
      }
      card.appendChild(ul);
      wrap.appendChild(card);
    }

    this._addRawView(wrap, text, bytes.length);
    return wrap;
  }

  analyzeForSecurity(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const normalized = lfNormalize(text);

    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: [],
    };

    // Format banner — always emitted. MOF is rare enough in user-supplied
    // files that the format alone justifies analyst attention.
    f.externalRefs.push({
      type: IOC.PATTERN,
      url: 'Managed Object Format (.mof) — WMI schema, often weaponised for T1546.003 persistence',
      severity: 'medium',
    });

    // ── CommandLineEventConsumer — most dangerous: arbitrary command on event ──
    // Pattern: `instance of CommandLineEventConsumer` + `CommandLineTemplate = "…"`.
    // We don't require the two to be in the same instance block — the
    // appearance of CommandLineEventConsumer is itself a high-signal IOC.
    const cleRe = /\binstance\s+of\s+CommandLineEventConsumer\b/gi;
    for (const m of normalized.matchAll(cleRe)) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: 'CommandLineEventConsumer — T1546.003 WMI persistence with arbitrary command execution',
        severity: 'critical',
        _highlightText: m[0],
        _sourceOffset: m.index,
        _sourceLength: m[0].length,
      });
    }

    // CommandLineTemplate values — the actual command. Capture for
    // analyst review and emit as IOC.COMMAND_LINE.
    const cmdTplRe = /\bCommandLineTemplate\s*=\s*"((?:\\.|[^"\\])*)"/gi;
    for (const m of normalized.matchAll(cmdTplRe)) {
      const cmd = m[1];
      if (!cmd) continue;
      pushIOC(f, {
        type: IOC.COMMAND_LINE,
        value: cmd,
        severity: 'high',
        note: 'CommandLineEventConsumer.CommandLineTemplate',
        highlightText: cmd,
      });
    }

    // ── ActiveScriptEventConsumer — VBScript/JScript on event ──
    const aseRe = /\binstance\s+of\s+ActiveScriptEventConsumer\b/gi;
    for (const m of normalized.matchAll(aseRe)) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: 'ActiveScriptEventConsumer — T1546.003 WMI persistence with script execution',
        severity: 'high',
        _highlightText: m[0],
        _sourceOffset: m.index,
        _sourceLength: m[0].length,
      });
    }

    // ScriptText values — the actual VBScript / JScript body. We don't
    // emit these as IOCs (they're prose) but we do offer the offset for
    // click-to-focus in the raw view.
    const scriptRe = /\bScriptText\s*=\s*"((?:\\.|[^"\\])*)"/gi;
    for (const m of normalized.matchAll(scriptRe)) {
      const body = m[1] || '';
      if (body.length < 4) continue;
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: 'ScriptText present — inline script payload in WMI consumer',
        severity: 'medium',
        _highlightText: m[0].slice(0, 80),
        _sourceOffset: m.index,
        _sourceLength: m[0].length,
      });
    }

    // ── __FilterToConsumerBinding — the wiring that makes persistence live ──
    const bindRe = /\binstance\s+of\s+__FilterToConsumerBinding\b/gi;
    for (const m of normalized.matchAll(bindRe)) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: '__FilterToConsumerBinding — wires WMI EventFilter to EventConsumer (T1546.003)',
        severity: 'high',
        _highlightText: m[0],
        _sourceOffset: m.index,
        _sourceLength: m[0].length,
      });
    }

    // ── __EventFilter — the trigger query ──
    const filtRe = /\binstance\s+of\s+__EventFilter\b/gi;
    for (const m of normalized.matchAll(filtRe)) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: '__EventFilter — WMI event-trigger query',
        severity: 'medium',
        _highlightText: m[0],
        _sourceOffset: m.index,
        _sourceLength: m[0].length,
      });
    }

    // WQL Query values — pull them out so analyst can read what events
    // the attacker is hooking (logon, process start, time window, etc.)
    const queryRe = /\bQuery\s*=\s*"((?:\\.|[^"\\])*)"/gi;
    for (const m of normalized.matchAll(queryRe)) {
      const q = m[1];
      if (!q) continue;
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `WQL Query: ${q.slice(0, 100)}`,
        severity: 'medium',
        _highlightText: q,
        _sourceOffset: m.index + m[0].indexOf(q),
        _sourceLength: q.length,
      });
    }

    // ── #pragma include(remote URL) — remote MOF compilation ──
    // mofcomp.exe honours `#pragma include` directives to fetch external
    // schema. A remote URL here is unambiguously hostile.
    const includeRe = /#pragma\s+include\s*\(\s*"([^"]+)"\s*\)/gi;
    for (const m of normalized.matchAll(includeRe)) {
      const target = m[1];
      if (/^https?:\/\//i.test(target)) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: `#pragma include points at remote URL — remote MOF compilation`,
          severity: 'high',
          _highlightText: target,
          _sourceOffset: m.index + m[0].indexOf(target),
          _sourceLength: target.length,
        });
        pushIOC(f, {
          type: IOC.URL,
          value: target,
          severity: 'high',
          note: '#pragma include',
          highlightText: target,
        });
      } else if (/^\\\\[^\\?]/.test(target)) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: `#pragma include points at UNC path — remote MOF compilation`,
          severity: 'high',
          _highlightText: target,
          _sourceOffset: m.index + m[0].indexOf(target),
          _sourceLength: target.length,
        });
        pushIOC(f, {
          type: IOC.UNC_PATH,
          value: target,
          severity: 'high',
          note: '#pragma include',
          highlightText: target,
        });
      }
    }

    // Risk calibration — same shape as the other small renderers.
    const refs = f.externalRefs;
    const highs = refs.filter(r => r.severity === 'high').length;
    const hasCrit = refs.some(r => r.severity === 'critical');
    const hasMed = refs.some(r => r.severity === 'medium');
    if (hasCrit) escalateRisk(f, 'critical');
    else if (highs >= 2) escalateRisk(f, 'high');
    else if (highs >= 1) escalateRisk(f, 'high');
    else if (hasMed) escalateRisk(f, 'medium');
    return f;
  }

  // ── Static summariser — used by render() and the test suite ──────────────
  // Pulls a list of every `instance of <Class>` block plus a count of
  // FilterToConsumerBinding entries. Cheap regex pull, no full MOF parse.
  static _summarize(text) {
    const classes = [];
    let bindings = 0;
    const re = /\binstance\s+of\s+([A-Za-z_][A-Za-z0-9_]*)/gi;
    let m;
    while ((m = re.exec(text)) !== null) {
      classes.push(m[1]);
      if (m[1] === '__FilterToConsumerBinding') bindings++;
    }
    return { classes, bindings };
  }

  _addRawView(wrap, text, byteLen) {
    const normalizedText = lfNormalize(text);
    const lines = normalizedText.split('\n');

    const sourcePane = document.createElement('div');
    sourcePane.className = 'mof-source plaintext-scroll';

    const table = document.createElement('table');
    table.className = 'plaintext-table';
    const maxLines = RENDER_LIMITS.MAX_TEXT_LINES_SMALL;
    const count = Math.min(lines.length, maxLines);
    let highlightedLines = null;
    if (typeof hljs !== 'undefined' && normalizedText.length <= 200000) {
      // MOF doesn't have a dedicated hljs language; fall back to
      // C-family highlighting which gets close enough for braces and
      // string literals.
      try {
        const result = hljs.highlight(normalizedText, { language: 'cpp', ignoreIllegals: true });
        highlightedLines = result.value.split('\n');
      } catch (_) { /* fallback to plain textContent */ }
    }
    for (let i = 0; i < count; i++) {
      const tr = document.createElement('tr');
      const tdNum = document.createElement('td');
      tdNum.className = 'plaintext-ln';
      tdNum.textContent = i + 1;
      const tdCode = document.createElement('td');
      tdCode.className = 'plaintext-code';
      if (highlightedLines && highlightedLines[i] !== undefined) {
        tdCode.innerHTML = highlightedLines[i] || '';
      } else {
        tdCode.textContent = lines[i];
      }
      tr.appendChild(tdNum); tr.appendChild(tdCode);
      table.appendChild(tr);
    }
    sourcePane.appendChild(table);
    wrap.appendChild(sourcePane);

    wrap._rawText = lfNormalize(text);
    wrap._showSourcePane = () => {
      sourcePane.scrollIntoView({ behavior: 'smooth', block: 'start' });
    };
  }

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
