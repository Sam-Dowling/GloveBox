// ════════════════════════════════════════════════════════════════════════════
// safelinks.js — SafeLink URL unwrapping for Proofpoint URLDefense (v1, v2,
// v3) and Microsoft SafeLinks. Extracted from `encoded-content-detector.js`
// (PLAN Track E2). Mounts as `EncodedContentDetector.unwrapSafeLink` so the
// existing static call sites (the IOC sweep in `_extractIOCsFromDecoded`,
// EML / image / PDF renderers) need no migration.
// ════════════════════════════════════════════════════════════════════════════

EncodedContentDetector.unwrapSafeLink = function unwrapSafeLink(url) {
  if (!url || typeof url !== 'string') return null;

  // ── Proofpoint URLDefense v3 ──
  // Format: https://urldefense.com/v3/__<URL>__;!!<token>
  const ppV3Re = /^https?:\/\/urldefense\.com\/v3\/__(.+?)__;/i;
  let m = url.match(ppV3Re);
  if (m) {
    let extracted = m[1];
    // Proofpoint v3 replaces certain chars with * followed by a hex code
    extracted = extracted.replace(/\*([0-9A-Fa-f]{2})/g, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16))
    );
    return { originalUrl: extracted, emails: [], provider: 'Proofpoint v3' };
  }

  // ── Proofpoint URLDefense v2 ──
  // Format: https://urldefense.proofpoint.com/v2/url?u=<encoded>&d=...
  const ppV2Re = /^https?:\/\/urldefense\.proofpoint\.com\/v2\/url\?/i;
  if (ppV2Re.test(url)) {
    try {
      const params = new URL(url).searchParams;
      let encoded = params.get('u');
      if (encoded) {
        // Proofpoint v2 encoding: - → %, _ → /
        encoded = encoded.replace(/-/g, '%').replace(/_/g, '/');
        const extracted = decodeURIComponent(encoded);
        return { originalUrl: extracted, emails: [], provider: 'Proofpoint v2' };
      }
    } catch (_) { /* malformed URL */ }
  }

  // ── Proofpoint URLDefense v1 ──
  // Format: https://urldefense.proofpoint.com/v1/url?u=<encoded>&k=...
  const ppV1Re = /^https?:\/\/urldefense\.proofpoint\.com\/v1\/url\?/i;
  if (ppV1Re.test(url)) {
    try {
      const params = new URL(url).searchParams;
      let encoded = params.get('u');
      if (encoded) {
        encoded = encoded.replace(/-/g, '%').replace(/_/g, '/');
        const extracted = decodeURIComponent(encoded);
        return { originalUrl: extracted, emails: [], provider: 'Proofpoint v1' };
      }
    } catch (_) { /* malformed URL */ }
  }

  // ── Microsoft SafeLinks ──
  // Format: https://*.safelinks.protection.outlook.com/?url=<encoded>&data=...
  const msRe = /^https?:\/\/[a-z0-9]+\.safelinks\.protection\.outlook\.com\/?\?/i;
  if (msRe.test(url)) {
    try {
      const params = new URL(url).searchParams;
      const encodedUrl = params.get('url');
      const data = params.get('data');
      const emails = [];

      // Extract email from data parameter
      if (data) {
        let dataDecoded = data;
        try { dataDecoded = decodeURIComponent(data); } catch (_) {}
        const emailRe = /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g;
        let em;
        while ((em = emailRe.exec(dataDecoded)) !== null) {
          if (!emails.includes(em[0])) emails.push(em[0]);
        }
      }

      if (encodedUrl) {
        const extracted = decodeURIComponent(encodedUrl);
        return { originalUrl: extracted, emails, provider: 'Microsoft SafeLinks' };
      }
    } catch (_) { /* malformed URL */ }
  }

  return null;
};
