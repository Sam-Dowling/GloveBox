// ESLint 9 flat config for Loupe.
//
// Loupe is a single-HTML-file app built by concatenating every file in
// src/ into one inline <script>. Because the architecture intentionally
// relies on cross-file globals (`App` extended across five app-*.js
// files, every renderer class referenced by name from
// renderer-registry.js, ten vendored libraries exposed as globals),
// this config is deliberately *minimal*: we run ESLint as a foot-gun
// catcher, not a style enforcer.
//
// What this config is for:
//   - Parse errors (free)
//   - No eval / no new Function (the single most important invariant
//     in the threat model — see SECURITY.md)
//   - Classic bug shapes: unreachable code, duplicate keys, const
//     reassignment, assignment-in-condition, dead function assigns,
//     broken typeof comparisons.
//
// What this config is NOT for:
//   - `no-undef` — would flag every cross-file class reference and
//     every vendored global. The build step is the source of truth.
//   - `no-implicit-globals` — the whole app is intentionally implicit
//     globals inside one concatenated script tag.
//   - Style rules (indent, quotes, semi, …). Out of scope.
//
// If a rule starts flagging real code in CI, prefer narrowing the
// rule's scope or adding a per-line `// eslint-disable-next-line`
// over broadening this config.

export default [
  {
    files: ['src/**/*.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'script',
    },
    linterOptions: {
      reportUnusedDisableDirectives: 'warn',
    },
    rules: {
      // ── Security invariants (hard errors) ────────────────────────
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-script-url': 'error',

      // ── Classic bug shapes (hard errors) ─────────────────────────
      'no-const-assign': 'error',
      'no-dupe-args': 'error',
      'no-dupe-class-members': 'error',
      'no-dupe-keys': 'error',
      'no-duplicate-case': 'error',
      'no-func-assign': 'error',
      'no-import-assign': 'error',
      'no-obj-calls': 'error',
      'no-unreachable': 'error',
      'no-unsafe-finally': 'error',
      'no-unsafe-negation': 'error',
      'use-isnan': 'error',
      'valid-typeof': 'error',
      'getter-return': 'error',
      'no-self-assign': 'error',
      'no-compare-neg-zero': 'error',

      // ── Suspicious patterns (warn — don't fail CI) ───────────────
      'no-cond-assign': ['warn', 'except-parens'],
      'no-sparse-arrays': 'warn',
      'no-unused-vars': ['warn', {
        args: 'none',          // unused fn args are common in renderer sigs
        varsIgnorePattern: '^_',
        caughtErrors: 'none',  // `catch (e)` with unused e is idiomatic here
      }],
      'no-empty': ['warn', { allowEmptyCatch: true }],
      'no-constant-condition': ['warn', { checkLoops: false }],
      'no-ex-assign': 'warn',

      // ── Explicitly OFF (architectural, see file header) ──────────
      'no-undef': 'off',
      'no-redeclare': 'off',
    },
  },
];
