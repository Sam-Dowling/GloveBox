// ════════════════════════════════════════════════════════════════════════════
// playwright.config.ts — Playwright wiring for Loupe's e2e test suite.
//
// Loupe is served as a single static file with no web server in any
// environment — including tests. We point Playwright at `file://` URLs
// of `docs/index.test.html` (the `--test-api` build emitted by
// `python scripts/build.py --test-api`). The test harness in
// `tests/helpers/playwright-helpers.ts` resolves the file URL relative
// to the repo root.
//
// Why no `webServer` config? Because spinning up an HTTP server would
// change the security context the tests exercise — the production app
// is opened straight from the filesystem (or a signed release, which
// applies the same CSP). Testing under file:// keeps the threat model
// faithful.
//
// Browsers: only Chromium. Loupe's CI matrix has historically been
// Chromium-only (Sigstore signing covers `docs/index.html`, which is
// browser-agnostic by virtue of the CSP). Adding Firefox / WebKit can
// be done by extending `projects` here, but should be a deliberate
// follow-up PR with green CI runs on every supported browser before
// the matrix lands.
//
// Reporters: `list` for human-readable local output, `github` when
// running under GitHub Actions (auto-detected via `process.env.CI`) so
// failures annotate the PR diff inline. The HTML reporter is left off
// to keep CI artefacts small — turn it on with `PWHTML=1` if needed.
// ════════════════════════════════════════════════════════════════════════════

import { defineConfig, devices } from '@playwright/test';
import * as path from 'node:path';

const REPO_ROOT = path.resolve(__dirname, '..');
const TEST_BUNDLE = path.join(REPO_ROOT, 'docs', 'index.test.html');

export default defineConfig({
  testDir: __dirname,
  testMatch: ['e2e-fixtures/**/*.spec.ts', 'e2e-ui/**/*.spec.ts'],

  // Single worker by default. Loupe's bundle is large (~9 MB) and each
  // page navigates to a `file://` URL; running many in parallel does
  // not meaningfully speed things up for the small fixture corpus we
  // ship today, and serialised output makes failure diagnosis easier.
  // Override locally with `--workers=N` if you want concurrency.
  workers: 1,
  fullyParallel: false,

  // Fail fast on local but never bail in CI — we want every failure
  // logged to the PR check run for triage.
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,

  reporter: process.env.CI ? [['github'], ['list']] : [['list']],

  use: {
    // Fail the test if the bundle takes longer than 30 s to settle on
    // the heaviest fixture. The current corpus completes well under
    // this — bumping it should prompt a perf investigation.
    actionTimeout: 30_000,
    navigationTimeout: 30_000,

    // baseURL is `file://` to the test bundle; tests pass the empty
    // path `''` to `page.goto()` to land on the index.
    baseURL: `file://${TEST_BUNDLE}`,

    // Capture context on first failure for triage. Trace / video off
    // by default to keep CI artefact size low; flip to 'on-first-retry'
    // by setting `PW_TRACE=1` in the CI environment when debugging a
    // flake.
    trace: process.env.PW_TRACE ? 'on-first-retry' : 'off',
    screenshot: 'only-on-failure',
    video: 'off',
  },

  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        // No CSP override; we want to exercise the production CSP.
        // No bypassCSP either — the test API never requires it because
        // every action goes through the same `_loadFile` entrypoint
        // that real ingress does.
      },
    },
  ],
});
