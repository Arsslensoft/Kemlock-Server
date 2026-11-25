<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/kemlock-wordmark-dark.svg">
    <img alt="Kemlock" src=".github/assets/kemlock-wordmark-light.svg" width="360">
  </picture>
</p>

<h3 align="center">Kemlock Server</h3>

<p align="center">
  A self-hosted, end-to-end encrypted sync server for Kemlock, inspired by Vaultwarden.
</p>

<p align="center">
  <a href="https://github.com/Arsslensoft/Kemlock-Server/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Arsslensoft/Kemlock-Server/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/Arsslensoft/Kemlock-Server/actions/workflows/audit.yml"><img alt="Audit" src="https://github.com/Arsslensoft/Kemlock-Server/actions/workflows/audit.yml/badge.svg"></a>
  <a href="https://github.com/Arsslensoft/Kemlock-Server/actions/workflows/fuzz.yml"><img alt="Fuzz" src="https://github.com/Arsslensoft/Kemlock-Server/actions/workflows/fuzz.yml/badge.svg"></a>
  <a href="https://github.com/Arsslensoft/Kemlock-Server/actions/workflows/codeql.yml"><img alt="CodeQL" src="https://github.com/Arsslensoft/Kemlock-Server/actions/workflows/codeql.yml/badge.svg"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/Arsslensoft/Kemlock-Server"><img alt="OpenSSF Scorecard" src="https://api.scorecard.dev/projects/github.com/Arsslensoft/Kemlock-Server/badge"></a>
  <a href="LICENSE"><img alt="Licence: AGPL-3.0-only" src="https://img.shields.io/badge/licence-AGPL--3.0--only-blue"></a>
  <br>
  <img alt="Rust 1.100" src="https://img.shields.io/badge/Rust-1.100-000000?logo=rust&logoColor=white">
  <a href="https://github.com/Arsslensoft/Kemlock-Server/pkgs/container/kemlock-server"><img alt="Docker image" src="https://img.shields.io/badge/image-ghcr.io%2Farsslensoft%2Fkemlock--server-2496ED?logo=docker&logoColor=white"></a>
  <a href="DCO"><img alt="DCO: signed off" src="https://img.shields.io/badge/DCO-signed--off-3fb950"></a>
  <img alt="SQLite, PostgreSQL, MySQL" src="https://img.shields.io/badge/database-SQLite%20%7C%20PostgreSQL%20%7C%20MySQL-336791">
  <img alt="ML-KEM-1024 + X25519" src="https://img.shields.io/badge/crypto-ML--KEM--1024%20%2B%20X25519-6f42c1">
  <img alt="Status: in development" src="https://img.shields.io/badge/status-in%20development-orange">
</p>

<p align="center">
  <a href="docs/self-hosting.md">Self-hosting</a> ·
  <a href="docs/crypto.md">Cryptography</a> ·
  <a href="docs/federation.md">Federation</a> ·
  <a href="docs/push-relay.md">Push relay (optional)</a> ·
  <a href="CONTRIBUTING.md">Contributing</a> ·
  <a href="SECURITY.md">Security policy</a> ·
  <a href="https://github.com/Arsslensoft/Kemlock">Kemlock app</a>
</p>

---

A self-hosted sync server for [Kemlock](https://github.com/Arsslensoft/Kemlock), the post-quantum
encrypted authenticator and password manager. It is inspired by Vaultwarden:

- **End-to-end encrypted.** Every item is sealed on the device that wrote it. The server stores
  ciphertext, wrapped keys, sizes and dates, and never holds a key that opens a vault.
- **Two APIs in one binary.** The Kemlock API carries every Kemlock kind with ML-KEM-1024 + X25519
  key sharing. The Bitwarden® API answers as Vaultwarden does, so Bitwarden apps and Amethystora
  Vault keep syncing.
- **Moves in from Vaultwarden.** A Vaultwarden data folder is copied as stored, nothing decrypted,
  and apps notice nothing.
- **Federation.** Servers can copy chosen vaults to each other as ciphertext, and Kemlock apps fall
  back to a replica when a vault's home server is down.
- **SSO without key escrow.** OpenID Connect decides who signs in; a trusted device, an approval
  from another device or the master password opens the vault.
- **Homelab friendly.** One static binary and multi-arch images for every architecture Vaultwarden
  supports, SQLite by default, PostgreSQL or MySQL when wanted.

Written in Rust (axum, SeaORM) in clean-architecture crates, with a React and TypeScript web vault
built into the binary.

## Documentation

| Page | What it covers |
|---|---|
| [Self-hosting](docs/self-hosting.md) | Installing on each platform, reverse proxies, checking downloads |
| [Cryptography](docs/crypto.md) | The byte formats every client and the server agree on |
| [Federation](docs/federation.md) | The formats two servers agree on to copy vaults to each other |
| [Push relay](docs/push-relay.md) | The contract with the optional hosted relay, a fallback for iPhones on a server with no Apple key |
| [Security policy](SECURITY.md) | Reporting a vulnerability |

## Status

The design is done and implementation is starting. Nothing here is ready to run yet.

## Contributing

Bug reports, fixes and docs are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) covers the Docker-based
dev setup, the checks CI runs, Conventional Commits and the DCO sign-off (`git commit -s`). Please
follow the [code of conduct](CODE_OF_CONDUCT.md). For questions, see [SUPPORT.md](SUPPORT.md); the
project is run as described in [GOVERNANCE.md](GOVERNANCE.md), and changes are listed in the
[changelog](CHANGELOG.md).

## Security

Report a vulnerability privately, with a
[GitHub security advisory](https://github.com/Arsslensoft/Kemlock-Server/security/advisories/new),
never in a public issue. [SECURITY.md](SECURITY.md) says what to include and what to expect.

## Licence

[AGPL-3.0](LICENSE). Anyone who runs a modified server for others must offer them its source.

## Trademarks

Bitwarden® is a registered trademark of Bitwarden Inc. Vaultwarden is a project by Daniel García and
its contributors. Kemlock is not affiliated with, endorsed by or sponsored by Bitwarden Inc. or the
Vaultwarden project; the names are used only to say which apps and servers Kemlock works with.
