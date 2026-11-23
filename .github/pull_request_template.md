## Summary

<!-- What changes, and why. A sentence or two. -->

## Linked issue

<!-- Fixes #123, or "none" for a small fix. A change to the design needs an issue first. -->

## Checklist

- [ ] The title is a Conventional Commit line, `type(scope): what the change does`
- [ ] Each commit is one change and has a `Signed-off-by:` line (`git commit -s`, see [CONTRIBUTING.md](../CONTRIBUTING.md))
- [ ] Tests are added or updated, and fmt, clippy, the tests and the web checks pass locally
- [ ] Docs are updated where the change makes them wrong
- [ ] No secrets, tokens, vault data or personal details are included
- [ ] `docs/crypto.md` byte formats: this change does not alter them, or it does and I say how below

## Byte-format and compatibility impact

<!-- Does this change anything in docs/crypto.md, docs/federation.md or an answer of the Bitwarden API? If so, what, and how do existing vaults and clients keep working? Otherwise write "none". -->
