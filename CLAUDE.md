# Kemlock Server

The Rust backend and React web vault, inspired by Vaultwarden, for Kemlock, Amethystora Vault and
Bitwarden apps. Licensed AGPL-3.0.

The design is the "Kemlock Server: design and architecture" doc
(https://claude.ai/artifact/2NWbdYSZaFK84mnLMWvx1Y), and its screens are on the design canvas
(https://claude.ai/artifact/4wvdwScsMsGu6NMSj6ptPo). Its Decisions table records what the owner
settled; follow it, and ask before departing from it.

The Kemlock app lives in the sibling repo `../kemlock` (git@github.com:Arsslensoft/Kemlock.git).

## Layout (planned)

- `crates/`: one Cargo workspace. Dependencies point inward only:
  - `kemlock-domain`: entities and rules, no I/O;
  - `kemlock-app`: one file per use case, and the port traits they call;
  - `kemlock-crypto`: ML-KEM-1024 + X25519, ML-DSA-65 + Ed25519, AES-256-GCM, `KMA1`, Argon2id,
    OPAQUE; aws-lc-rs natively, RustCrypto in WebAssembly;
  - adapters: `kemlock-store-sql`, `kemlock-blob`, `kemlock-identity`, `kemlock-notify`,
    `kemlock-federation`;
  - web: `kemlock-api-kem`, `kemlock-api-bw`, `kemlock-api-fed`, `kemlock-api-admin`;
  - binaries: `kemlock-server`, `kemlock-cli`;
  - shared with other clients: `kemlock-client`, `kemlock-import`.
- `web/`: the React and TypeScript web vault and admin console, built into the server binary.
- `docs/`: design notes that are part of the repo.

## Compatibility

- The Bitwarden API answers exactly as Vaultwarden does, quirks included. Kemlock and Amethystora
  Vault were built against Vaultwarden, and contract tests replay their traffic.
- Formats the Kemlock app writes (vault, `KMA1` attachments, sync files, invites, the items it
  keeps in Vaultwarden) stay byte for byte. Its fixtures are in `../kemlock/mobile/test/fixtures`.

## Commits

Commit one change at a time, as the Kemlock and Amethystora repos do. Each feature, fix, test,
chore, docs change or refactor gets its own commit; never lump unrelated work together.

- Messages follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/#specification):
  `type(scope): what the change does`, in plain words, lowercase after the colon, no trailing period.
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
- AI agents end the message with an `Assisted-by: <model> via <tool>` footer, e.g.
  `Assisted-by: Claude Opus 5.5 via Claude Code`, and no `Co-Authored-By` line.
