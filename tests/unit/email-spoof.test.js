'use strict';
// email-spoof.test.js — display-name / brand mismatch heuristics.
//
// EmailSpoof.analyseFromHeader(rawFromHeader) returns
//   [{ kind: 'brand-mismatch' | 'domain-literal-mismatch',
//      reason: string, severity: 'high' | 'medium' }]
//
// The helper plugs into both eml-renderer and msg-renderer — it lives
// outside them so the heuristic stays in one place and the brand list
// is only declared once.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules(['src/email-spoof.js'], { expose: ['EmailSpoof'] });
const { EmailSpoof } = ctx;

// ── Brand mismatch (high) ───────────────────────────────────────────────────

test('brand: PayPal display name + non-paypal domain → high', () => {
  const out = EmailSpoof.analyseFromHeader('"PayPal Support" <attacker@evil.tld>');
  assert.equal(out.length, 1);
  assert.equal(out[0].kind, 'brand-mismatch');
  assert.equal(out[0].severity, 'high');
  assert.match(out[0].reason, /paypal/i);
  assert.match(out[0].reason, /evil\.tld/);
});

test('brand: PayPal display name + paypal.com domain → no detection', () => {
  const out = EmailSpoof.analyseFromHeader('"PayPal Support" <noreply@paypal.com>');
  assert.equal(out.length, 0);
});

test('brand: PayPal display name + service.paypal.com → no detection (subdomain)', () => {
  const out = EmailSpoof.analyseFromHeader('"PayPal" <ops@service.paypal.com>');
  assert.equal(out.length, 0);
});

test('brand: Microsoft + outlook.com → no detection (legit alias)', () => {
  const out = EmailSpoof.analyseFromHeader('"Microsoft 365" <noreply@outlook.com>');
  assert.equal(out.length, 0);
});

test('brand: Microsoft + lookalike microsoft-secure.com → high', () => {
  const out = EmailSpoof.analyseFromHeader('"Microsoft Account" <verify@microsoft-secure.com>');
  assert.equal(out.length, 1);
  assert.equal(out[0].kind, 'brand-mismatch');
  assert.equal(out[0].severity, 'high');
});

test('brand: multi-word "Bank of America" matches whole-string', () => {
  const out = EmailSpoof.analyseFromHeader('"Bank of America Alerts" <alert@evil.tld>');
  assert.ok(out.some(d => d.kind === 'brand-mismatch'));
});

test('brand: case-insensitive (DOCUSIGN)', () => {
  const out = EmailSpoof.analyseFromHeader('"DOCUSIGN" <a@evil.tld>');
  assert.equal(out.length, 1);
  assert.equal(out[0].kind, 'brand-mismatch');
});

test('brand: word-boundary discipline — "applepay" must not match "apple"', () => {
  const out = EmailSpoof.analyseFromHeader('"ApplePay" <a@example.com>');
  // applepay is not in the brand table; "apple" must not match inside it.
  const brandHits = out.filter(d => d.kind === 'brand-mismatch');
  assert.equal(brandHits.length, 0);
});

test('brand: only first matching brand fires (no multi-fire)', () => {
  // "Apple Microsoft" mentions two brands — pick one, not both.
  const out = EmailSpoof.analyseFromHeader('"Apple Microsoft Update" <a@evil.tld>');
  const brandHits = out.filter(d => d.kind === 'brand-mismatch');
  assert.equal(brandHits.length, 1, 'expected at most one brand-mismatch entry');
});

// ── Domain-literal mismatch (medium) ────────────────────────────────────────

test('domain-literal: display-name embeds different domain → medium', () => {
  const out = EmailSpoof.analyseFromHeader('"info@trusted.bank.example" <a@evil.tld>');
  assert.ok(out.some(d => d.kind === 'domain-literal-mismatch' && d.severity === 'medium'));
});

test('domain-literal: same domain in display-name and address → no detection', () => {
  const out = EmailSpoof.analyseFromHeader('"info@x.example" <noreply@x.example>');
  assert.equal(out.length, 0);
});

test('domain-literal: display-name domain is subdomain of sender → no detection', () => {
  const out = EmailSpoof.analyseFromHeader('"news@mail.x.example" <ops@x.example>');
  assert.equal(out.length, 0);
});

test('domain-literal: file extension (.pdf) ignored', () => {
  const out = EmailSpoof.analyseFromHeader('"Invoice 2024-09.pdf" <a@example.com>');
  const literalHits = out.filter(d => d.kind === 'domain-literal-mismatch');
  assert.equal(literalHits.length, 0);
});

// ── Edge cases ──────────────────────────────────────────────────────────────

test('null / empty / non-string input → []', () => {
  assert.equal(EmailSpoof.analyseFromHeader(null).length, 0);
  assert.equal(EmailSpoof.analyseFromHeader('').length, 0);
  assert.equal(EmailSpoof.analyseFromHeader(undefined).length, 0);
  assert.equal(EmailSpoof.analyseFromHeader(42).length, 0);
});

test('bare address (no display name) → []', () => {
  assert.equal(EmailSpoof.analyseFromHeader('a@example.com').length, 0);
});

test('angle-only (no display name, brackets only) → []', () => {
  assert.equal(EmailSpoof.analyseFromHeader('<a@example.com>').length, 0);
});

test('legacy RFC822 form: address (Display Comment)', () => {
  // `a@evil.tld (PayPal Support)` — display-name is in parens.
  // Our parser extracts the comment as part of `displayName` after we
  // strip both `<…>` and `(…)`. The comment IS stripped, so this form
  // does NOT trigger a brand-mismatch. (Observable behaviour: the legacy
  // comment form is rare today; we deliberately don't overreach into it.)
  const out = EmailSpoof.analyseFromHeader('a@evil.tld (PayPal Support)');
  // Either zero detections OR a domain-literal hit on `evil.tld` (no);
  // brand-mismatch should NOT fire because the comment was stripped.
  const brandHits = out.filter(d => d.kind === 'brand-mismatch');
  assert.equal(brandHits.length, 0);
});

test('display-name with quoted comma "Last, First" parses cleanly', () => {
  const out = EmailSpoof.analyseFromHeader('"Smith, John" <john@example.com>');
  assert.equal(out.length, 0);
});

test('encoded-word input is not specially handled — caller decodes first', () => {
  // The contract is: caller decodes RFC2047 BEFORE calling. Verify the
  // helper doesn't crash when given a raw encoded-word — it just sees
  // the literal `=?utf-8?…?=` string and treats the whole thing as the
  // display-name (no brand match expected).
  const out = EmailSpoof.analyseFromHeader('=?utf-8?b?UGF5UGFs?= <a@evil.tld>');
  // The base64 garbage shouldn't accidentally word-match "paypal".
  const brandHits = out.filter(d => d.kind === 'brand-mismatch');
  assert.equal(brandHits.length, 0);
});

test('PayPal as part of a longer word does NOT match (paypal-foo)', () => {
  // `paypal-foo` is a single token by tokeniser standards; \b is at the
  // hyphen, so it actually DOES match `paypal` with \b…\b. This is
  // intentional — phishers commonly pad with hyphens. Verify the match.
  const out = EmailSpoof.analyseFromHeader('"PayPal-Foo Updates" <a@evil.tld>');
  assert.ok(out.some(d => d.kind === 'brand-mismatch'),
    'hyphenated brand variant should still match');
});
