<!--
Thanks for contributing to Loupe!

Before submitting, please confirm the checkboxes below. Anything that touches
src/, vendor/, or scripts/build.py almost always requires a matching docs change —
docs drift is the primary rot vector in this repo.
-->

## Summary

<!-- What does this PR do, in one or two sentences? -->

## Type of change

- [ ] Bug fix
- [ ] New file format / renderer
- [ ] New or updated YARA rule
- [ ] New UI feature / keyboard shortcut
- [ ] Vendored library add / upgrade
- [ ] Security-relevant default (CSP, parser limits, sandbox flag)
- [ ] Documentation only
- [ ] Other (describe below)

## Motivation / context

<!-- Why is this change needed? Link any related issue. -->

Closes #

## Build + verification

- [ ] `python make.py` runs cleanly end-to-end (verify vendors → rebuild `docs/index.html` → renderer-contract check)
- [ ] Manually smoke-tested in a browser with at least one relevant sample from `examples/`

*(`make.py` is a thin orchestrator — if you'd rather run them separately,
`python scripts/verify_vendored.py && python scripts/build.py && python scripts/check_renderer_contract.py`
is equivalent.)*

## Docs touched (tick whichever apply)

Per the doc-map in `CONTRIBUTING.md`:

- [ ] `README.md` — headline user-visible capability
- [ ] `FEATURES.md` — user-facing format / capability / shortcut reference
- [ ] `SECURITY.md` — CSP, parser limits, sandbox, threat-model boundary
- [ ] `CONTRIBUTING.md` — architecture, renderer contracts, gotchas, persistence keys
- [ ] `VENDORED.md` — vendored library row rotated (**required** for any vendor change)
- [ ] None — this is a pure code / bug fix with no user-visible or security-relevant behaviour change

## Security considerations

- [ ] This change does not add any `eval`, `new Function`, or `Function()` call site
- [ ] This change does not relax the top-level Content-Security-Policy in `scripts/build.py`
- [ ] This change does not introduce any network request (fetch, XHR, WebSocket, external `<img>`, etc.)

<!--
If any of the three boxes above are unticked, please explain in detail below
why the exception is justified. Most PRs should be able to tick all three.
-->

## Additional notes
