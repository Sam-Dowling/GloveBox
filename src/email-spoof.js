'use strict';
// ════════════════════════════════════════════════════════════════════════════
// email-spoof.js — display-name / brand impersonation heuristics for EML/MSG.
//
// The eml-renderer already detects three kinds of header anomaly:
//   • Reply-To ≠ From (T2.3)
//   • freemail-domain From with authority-role display name (T2.4)
//   • Return-Path / Message-ID domain ≠ From domain (T2.5)
//
// This helper closes the most common remaining phishing-pretext signal:
// the display-name carries a recognisable BRAND or a literal DOMAIN that
// disagrees with the actual sender domain. APWG / PhishLabs IR reports
// rank this pattern alongside compromised-account phishing as the top-two
// vectors year over year.
//
// Detection grammar:
//   Input:  raw `From:` header value, e.g.
//             `"PayPal Support <legit@paypal.com>" <attacker@evil.tld>`
//   Output: array of { kind, reason, severity }
//
//   We emit at most one detection per heuristic; severity is 'high' for
//   brand mismatches (the canonical phishing primitive), 'medium' for
//   raw-domain mismatches (someone embedded a domain literal in the
//   display-name that disagrees with the sender — slightly noisier,
//   could be legitimate "via" forwarding).
//
// Caller responsibility:
//   • Collapse and decode RFC2047 encoded-words BEFORE handing the value
//     in — eml-renderer already does this in its `_decodeHeader` path.
//   • Pass the raw From with the address in `<…>`. We extract both halves.
//
// Used by: eml-renderer, msg-renderer
// Depends on: nothing (pure data + regex)
// ════════════════════════════════════════════════════════════════════════════

// Curated list of frequently-impersonated brands. Each entry maps a set of
// keyword tokens (matched as whole-word substrings, case-insensitive) to
// the canonical sender domain(s). A display-name containing a keyword
// triggers a check; if the From address's effective domain doesn't end
// in any of the legitimate domains, a high-severity detection fires.
//
// "Effective domain" = the registrable domain (eTLD+1) plus immediate
// subdomains. We don't ship a full PSL — instead we accept any domain
// that ENDS in `.<legit>` or equals `<legit>`. For very-short legit
// domains (e.g. `t.co`), the keyword match is the gate, not the domain
// suffix, so false positives are bounded.
//
// Adding a brand: keep it to canonical English-spelling terms widely-cited
// in phishing kit corpora; obscure brands belong in user-supplied YARA.

const _BRAND_TABLE = Object.freeze([
  { keywords: ['paypal'],            domains: ['paypal.com', 'paypal.co.uk'] },
  { keywords: ['microsoft', 'msft'], domains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'azure.com', 'sharepoint.com', 'onmicrosoft.com', 'msn.com'] },
  { keywords: ['apple', 'icloud'],   domains: ['apple.com', 'icloud.com', 'me.com', 'mac.com'] },
  { keywords: ['google', 'gmail'],   domains: ['google.com', 'gmail.com', 'googlemail.com', 'youtube.com'] },
  { keywords: ['amazon', 'aws'],     domains: ['amazon.com', 'amazon.co.uk', 'aws.amazon.com', 'audible.com', 'amazonpay.com'] },
  { keywords: ['facebook', 'meta'],  domains: ['facebook.com', 'facebookmail.com', 'meta.com', 'fb.com', 'instagram.com'] },
  { keywords: ['linkedin'],          domains: ['linkedin.com'] },
  { keywords: ['netflix'],           domains: ['netflix.com'] },
  { keywords: ['adobe'],             domains: ['adobe.com', 'adobesign.com'] },
  { keywords: ['dropbox'],           domains: ['dropbox.com', 'dropboxmail.com'] },
  { keywords: ['docusign'],          domains: ['docusign.com', 'docusign.net'] },
  { keywords: ['github'],            domains: ['github.com'] },
  { keywords: ['slack'],             domains: ['slack.com'] },
  { keywords: ['zoom'],              domains: ['zoom.us'] },
  { keywords: ['ebay'],              domains: ['ebay.com', 'ebay.co.uk'] },
  { keywords: ['stripe'],            domains: ['stripe.com'] },
  { keywords: ['fedex'],             domains: ['fedex.com'] },
  { keywords: ['ups',  'parcel'],    domains: ['ups.com'] },
  { keywords: ['dhl'],               domains: ['dhl.com'] },
  { keywords: ['usps'],              domains: ['usps.com'] },
  { keywords: ['chase'],             domains: ['chase.com', 'jpmorganchase.com'] },
  { keywords: ['wells fargo'],       domains: ['wellsfargo.com'] },
  { keywords: ['bank of america',
                'bankofamerica'],    domains: ['bankofamerica.com', 'bofa.com'] },
  { keywords: ['hsbc'],              domains: ['hsbc.com', 'hsbc.co.uk'] },
  { keywords: ['barclays'],          domains: ['barclays.com', 'barclays.co.uk'] },
  { keywords: ['capital one'],       domains: ['capitalone.com'] },
  { keywords: ['citibank', 'citi'],  domains: ['citi.com', 'citibank.com'] },
  { keywords: ['american express',
                'amex'],              domains: ['americanexpress.com', 'aexp.com'] },
  { keywords: ['intuit', 'turbotax',
                'quickbooks'],        domains: ['intuit.com', 'quickbooks.com'] },
  { keywords: ['twitter', 'x corp'], domains: ['twitter.com', 'x.com'] },
]);

class EmailSpoof {
  /**
   * Analyse a raw `From:` header value for display-name / domain mismatch.
   *
   * @param {string} fromHeader  raw header value (after RFC2047 decoding).
   * @returns {Array<{kind:string, reason:string, severity:string}>}
   *   `kind`: 'brand-mismatch' | 'domain-literal-mismatch'
   */
  static analyseFromHeader(fromHeader) {
    const out = [];
    if (!fromHeader || typeof fromHeader !== 'string') return out;
    const { displayName, addrDomain } = EmailSpoof._split(fromHeader);
    if (!displayName || !addrDomain) return out;

    // ── 1. Brand-mismatch ────────────────────────────────────────────
    // Display-name contains a known brand keyword and address domain
    // doesn't sit under any of the brand's legitimate domains.
    const dnLower = displayName.toLowerCase();
    for (const brand of _BRAND_TABLE) {
      let kwHit = null;
      for (const kw of brand.keywords) {
        // Whole-word match — `applepay` shouldn't trip "apple", but
        // `Apple Inc` should. Multi-word keywords (e.g. "wells fargo")
        // are handled with a literal-string includes() since they
        // already span a word boundary.
        if (kw.includes(' ')) {
          if (dnLower.includes(kw)) { kwHit = kw; break; }
        } else {
          // \b on the keyword endpoints. The keyword is hard-coded
          // (no user input) so the regex source is safe.
          /* safeRegex: builtin */
          const re = new RegExp(`\\b${kw}\\b`, 'i');
          if (re.test(dnLower)) { kwHit = kw; break; }
        }
      }
      if (!kwHit) continue;
      // Compare addrDomain to brand.domains: addrDomain MUST end with
      // one of the legit domains (preceded by `.` or be exact match).
      const matched = brand.domains.some(d =>
        addrDomain === d || addrDomain.endsWith('.' + d));
      if (!matched) {
        out.push({
          kind: 'brand-mismatch',
          reason: `Display name claims "${kwHit}" but sender domain is "${addrDomain}" — expected one of ${brand.domains.slice(0, 3).join(', ')}`,
          severity: 'high',
        });
        // First brand wins — avoid noisy multi-fires for display
        // names that happen to mention several brands.
        break;
      }
    }

    // ── 2. Domain-literal mismatch ───────────────────────────────────
    // Display-name embeds a literal domain (e.g. "Bob <bob@paypal.com>"
    // as the displayed text) that disagrees with the actual sender
    // domain. Strong signal even when the brand list misses, since the
    // attacker's intent is explicit.
    const literalRe = /\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b/gi;
    let m;
    const seen = new Set();
    while ((m = literalRe.exec(dnLower)) !== null) {
      const cand = m[1].toLowerCase();
      // Skip common non-domain TLD-like tokens (file extensions etc.).
      if (/\.(?:doc|pdf|txt|exe|jpg|png|gif)$/i.test(cand)) continue;
      // Need at least two dot-separated parts AND a recognisable TLD.
      if (!/\.[a-z]{2,}$/.test(cand)) continue;
      if (seen.has(cand)) continue;
      seen.add(cand);
      // Match if addrDomain ENDS in the literal or vice-versa — the
      // mismatch fires only when neither contains the other (so
      // `mail.paypal.com` versus `paypal.com` is benign).
      if (addrDomain.endsWith(cand) || cand.endsWith(addrDomain)) continue;
      out.push({
        kind: 'domain-literal-mismatch',
        reason: `Display name embeds "${cand}" but sender domain is "${addrDomain}"`,
        severity: 'medium',
      });
      break; // one per header
    }

    return out;
  }

  // Split a raw From into `displayName` (text outside angle brackets,
  // de-quoted) and `addrDomain` (lowercase, after `@`). Robust to
  // permutations actually seen in the wild:
  //   `"Name" <a@b.c>`
  //   `Name <a@b.c>`
  //   `a@b.c (Comment)`           ← bare-address legacy form (RFC822)
  //   `a@b.c`                      ← bare address only (no display name)
  //   `<a@b.c>`                    ← angle-only
  static _split(raw) {
    let s = String(raw).trim();
    // Address: prefer `<…>` group, else any e-mail-shaped substring.
    let addr = '';
    const angle = s.match(/<\s*([^>\s]+@[^>\s]+)\s*>/);
    if (angle) addr = angle[1];
    else {
      const bare = s.match(/[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/);
      if (bare) addr = bare[0];
    }
    const addrDomain = addr.includes('@') ? addr.split('@')[1].toLowerCase() : '';
    // Display name: strip angle group, RFC822 (comment), and quotes.
    let dn = s.replace(/<[^>]*>/g, ' ').replace(/\([^)]*\)/g, ' ');
    dn = dn.replace(/["']/g, ' ').trim();
    // If the only thing left IS the address (bare-address form), drop it
    // from the display-name so we don't compare "a@b.c" against itself.
    if (dn === addr) dn = '';
    return { displayName: dn, addrDomain };
  }
}

if (typeof window !== 'undefined') window.EmailSpoof = EmailSpoof;
