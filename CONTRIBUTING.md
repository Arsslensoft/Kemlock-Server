# Contributing to Kemlock Server

Thank you for helping. This page covers how to set up, what to run before you open a pull request,
how to write commits and what happens next. Everything here is licensed like the rest of the
project, [AGPL-3.0](LICENSE).

Please read the [code of conduct](CODE_OF_CONDUCT.md) first. To report a security flaw, do not open
an issue or a pull request: follow the [security policy](SECURITY.md).

## Before you start

- For a bug, search the [issues](https://github.com/Arsslensoft/Kemlock-Server/issues) first, then
  open one with the bug form.
- For a feature or a change in behaviour, open an issue or a
  [discussion](https://github.com/Arsslensoft/Kemlock-Server/discussions) before you write code.
  The design decisions are settled by the maintainer (see [GOVERNANCE.md](GOVERNANCE.md)), and a
  pull request that departs from them is likely to be declined, however good the code.
- Small fixes, tests and documentation need no discussion first.
- Two things are fixed by design: the Bitwarden API must answer exactly as Vaultwarden does, quirks
  included, and the byte formats in [docs/crypto.md](docs/crypto.md) and
  [docs/federation.md](docs/federation.md) stay byte for byte. Changing either needs an issue first.

## Set up

You need Git, Docker and Node 22.12 or newer. You do not need Rust on your machine: `tools/cargo.sh`
runs cargo in a Rust container (the toolchain in `rust-toolchain.toml`), and keeps the registry and
the build output in Docker volumes, not in your checkout.

```sh
git clone https://github.com/Arsslensoft/Kemlock-Server.git
cd Kemlock-Server

tools/cargo.sh build                      # the server and every crate
tools/cargo.sh test --workspace           # the Rust tests

cd web
npm ci
npm run dev                               # the web vault on http://localhost:5173
```

`npm run dev` proxies to a server on `localhost:8000`. Start one with
`DOMAIN=http://localhost:5173 ROCKET_PORT=8000 tools/cargo.sh run -p kemlock-server`; it prints a
one-time setup code in its log on first run. If you have Rust installed, you can call `cargo`
directly instead of `tools/cargo.sh`. More about the web app is in [web/README.md](web/README.md),
and about running the server in [docs/self-hosting.md](docs/self-hosting.md).

## Run the checks

CI runs these on every pull request, so run them first. With Docker only, prefix each cargo command
with `tools/cargo.sh`; to run several, pass one quoted command line.

```sh
# Rust
tools/cargo.sh fmt --all --check
tools/cargo.sh clippy --workspace --all-targets --locked -- -D warnings
tools/cargo.sh test --workspace --locked --exclude kemlock-contract-tests

# Web (in web/)
npm run typecheck                         # tsc --noEmit
npm test                                  # Vitest
npm run build                             # then Playwright runs against the built server
npm run e2e                               # Playwright journeys and axe checks
```

- Fix formatting with `cargo fmt --all`. Clippy warnings are errors.
- The Playwright journeys run against a real server that embeds the built web vault. Build the web
  vault with `npm run build`, build the server with `cargo build -p kemlock-server --features web`,
  and `e2e/global-setup.ts` starts it on a free port with a fresh data folder. Playwright's
  browsers come from `npx playwright install chromium`. `npm run e2e:sso` runs the sign-in
  journeys against an identity provider.
- The contract tests (`kemlock-contract-tests`) replay the traffic of the Kemlock app and
  Amethystora Vault against the Bitwarden API. They need those repositories checked out beside
  this one, which CI does for you, so they are fine to leave to CI.
- If you change anything in `kemlock-crypto` or `kemlock-federation` that touches a format,
  regenerate the test vectors with the two `cargo run ... --features vectors` commands in
  `.github/workflows/ci.yml` and commit the result; CI fails on a difference.
- Dependencies are checked by `cargo deny` and `cargo vet`. A new crate needs a reason in the commit
  message, and may need a `cargo vet` entry.

## Write good changes

- Follow the style around you, and keep dependencies pointing inward only: the layout is in
  [CLAUDE.md](CLAUDE.md).
- Every behaviour change comes with a test. A bug fix includes the regression test that fails
  without it.
- Change the docs that the change makes wrong, in the same pull request.
- Do not commit secrets, real vault data, or a real person's details, not even in a test.

## Commits

Commit one change at a time. Each feature, fix, test, chore, docs change or refactor gets its own
commit; never lump unrelated work together.

- Messages follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/#specification):
  `type(scope): what the change does`, in plain words, lowercase after the colon, no trailing
  period. Release notes come from these, so they should read well on their own.
- Types: `feat`, `fix`, `test`, `chore`, `docs`, `refactor`, `revert`.
- The scope is the area touched: `domain`, `app`, `crypto`, `store`, `blob`, `identity`, `notify`,
  `federation`, `api`, `bitwarden`, `admin`, `web`, `import`, `client`, `cli`, `server`, `sync`,
  `sso`, `docker`, `ci`, `deps`, `docs`.
- A test goes in its own `test(scope)` commit after the code it checks, unless it is the regression
  test of a fix, which goes in with the fix.
- Lockfile and dependency changes go in with the feature that needs them, or in their own
  `chore(deps)` commit.
- The body, wrapped at about 72 columns, says what was wrong or missing and why the change fixes it.
  Name other commits by their short hash.

For example:

```text
fix(sync): stop dropping a folder renamed on two devices

A rename that arrived while another was being applied was ignored, so the
older name came back after the next sync. The later write now wins, as in
the design notes. Fixes #123.

Signed-off-by: Your Name <you@example.com>
```

## Sign off your commits (DCO)

Every commit needs a `Signed-off-by:` line. It is how you say that you wrote the change, or have the
right to submit it, under this project's licence. We use the
[Developer Certificate of Origin 1.1](https://developercertificate.org/) (the text is in [DCO](DCO)),
which is a short statement and not a contract: you keep your copyright, and no agreement needs
signing.

Add the line with `git commit -s`:

```sh
git commit -s -m "fix(sync): stop dropping a folder renamed on two devices"
```

That adds `Signed-off-by: Your Name <you@example.com>`, taken from your `user.name` and
`user.email`. Use your real name, as the DCO asks. To sign a commit you already made, run
`git commit --amend -s --no-edit`; for a branch, `git rebase --signoff main`, then
`git push --force-with-lease` to your own branch.

The sign-off is a person's promise, so an AI tool cannot give it for you. If you used one, end the
message with an `Assisted-by: <model> via <tool>` footer, for example
`Assisted-by: Claude Sonnet 5.5 via Claude Code`, no `Co-Authored-By` line, and add your own
sign-off after reading and understanding the change.

## Pull requests

1. Fork the repository, and branch from `main`.
2. Make your commits as above, and run the checks.
3. Open the pull request. Its title is a Conventional Commit line, and the template asks for the
   rest.
4. A maintainer reviews it. CI must be green, and the maintainer must approve. Expect questions and
   requests for changes; answer them with new commits, and we squash or rebase at merge.
5. Changes to `crates/kemlock-crypto`, `docs/crypto.md` and `.github/` always get the lead
   maintainer's review (see [CODEOWNERS](.github/CODEOWNERS)).

A good pull request:

- does one thing, and is small enough to review in one sitting;
- links its issue, and says what changed and why, not only how;
- has tests, and the docs it changes;
- says whether it changes a byte format in `docs/crypto.md` or an answer of the Bitwarden API;
- passes CI, and contains no unrelated formatting or refactoring.

Reviews are done by volunteers. If a pull request has had no answer for two weeks, a polite comment
is welcome.

## Questions

Ask in [GitHub Discussions](https://github.com/Arsslensoft/Kemlock-Server/discussions); see
[SUPPORT.md](SUPPORT.md).
