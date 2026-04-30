// ════════════════════════════════════════════════════════════════════════════
// ioc-extract.js — IOC extraction from decoded payloads.
//
// Scans a decoded byte buffer for URLs, emails, IPs, Windows + UNC paths and
// returns an IOC[] tagged with `IOC.*` constants and severity hints. URLs are
// fed through `EncodedContentDetector.unwrapSafeLink` so Proofpoint /
// Microsoft SafeLinks wrappers contribute both the wrapper and the unwrapped
// inner URL (and any encoded recipient emails). UTF-16LE is decoded as a
// fallback so PowerShell `-EncodedCommand` blobs surface their IOCs too.
//
// Depends on globals from `src/constants.js`: `IOC`, `_trimPathExtGarbage`.
// Mounted via `Object.assign(EncodedContentDetector.prototype, …)`.
// ════════════════════════════════════════════════════════════════════════════

Object.assign(EncodedContentDetector.prototype, {
  _extractIOCsFromDecoded(bytes) {
    // Try UTF-8 first, fall back to UTF-16LE (PowerShell -EncodedCommand uses UTF-16LE)
    let text = this._tryDecodeUTF8(bytes);
    if (!text || text.length < 8) text = this._tryDecodeUTF16LE(bytes);
    if (!text || text.length < 8) return [];

    const iocs = [];
    const seen = new Set();
    const add = (type, val, sev, note) => {
      val = (val || '').trim().replace(/[.,;:!?)\]>]+$/, '');
      if (!val || val.length < 4 || val.length > 400 || seen.has(val)) return;
      seen.add(val);
      const entry = { type, url: val, severity: sev };
      if (note) entry.note = note;
      iocs.push(entry);
    };

    // Process URLs with SafeLink unwrapping.
    // FP-suppression: gibberish post-XOR / post-Hex output occasionally
    // contains the substring `http://` followed by random bytes, which
    // the URL regex cheerfully matches. Sanity-check the hostname:
    //   • must contain a dot (no `http://abc/...` w/o domain);
    //   • must NOT start with `0x` (hex-decode artefact);
    //   • bracketed IPv6 form must be properly closed.
    for (const m of text.matchAll(/https?:\/\/[^\s"'<>()\[\]{}\u0000-\u001F]{6,}/g)) {
      const url = (m[0] || '').trim().replace(/[.,;:!?)\]>]+$/, '');
      // Extract hostname portion for sanity check.
      const hostMatch = url.match(/^https?:\/\/([^\/\s?#]+)/i);
      if (!hostMatch) continue;
      const host = hostMatch[1];
      // IPv6 in bracket form: must be correctly bracketed.
      if (host.startsWith('[')) {
        if (!host.includes(']')) continue;
      } else {
        // Non-IPv6: must contain a literal dot in the hostname.
        if (!host.includes('.')) continue;
        // Hex-decode artefact: hostnames don't start with `0x`.
        if (/^0x/i.test(host)) continue;
      }
      const unwrapped = EncodedContentDetector.unwrapSafeLink(url);
      if (unwrapped) {
        // Add wrapper URL at info level
        add(IOC.URL, url, 'medium', `${unwrapped.provider} wrapper`);
        // Add extracted URL at high severity (found in encoded content)
        add(IOC.URL, unwrapped.originalUrl, 'high', `Extracted from ${unwrapped.provider}`);
        // Add any extracted emails
        for (const email of unwrapped.emails) {
          add(IOC.EMAIL, email, 'high', 'Extracted from SafeLinks');
        }
      } else {
        add(IOC.URL, url, 'high');
      }
    }

    for (const m of text.matchAll(/\b[a-zA-Z0-9._%+\-]{2,}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,6}\b/g))
      add(IOC.EMAIL, m[0], 'medium');
    for (const m of text.matchAll(/(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![\d.])/g)) {
      const parts = m[0].split('.').map(Number);
      if (parts.every(p => p <= 255) && !m[0].startsWith('0.') && parts.join('').length >= 5) add(IOC.IP, m[0], 'high');
    }
    // ReDoS-hardened: bounded quantifiers on path component / depth so
    // adversarial unterminated strings can't backtrack catastrophically.
    // See src/ioc-extract.js for the bounds rationale (NTFS component
    // 255, max depth 32).
    for (const m of text.matchAll(/[A-Za-z]:\\(?:[\w\-. ]{1,255}\\){1,32}[\w\-. ]{2,255}/g))
      add(IOC.FILE_PATH, _trimPathExtGarbage(m[0]), 'medium');
    for (const m of text.matchAll(/\\\\[\w.\-]{2,255}(?:\\[\w.\-]{1,255}){1,32}/g))
      add(IOC.UNC_PATH, m[0], 'medium');

    return iocs;
  },
});
