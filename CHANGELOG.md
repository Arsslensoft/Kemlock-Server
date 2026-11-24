# Changelog

All notable changes to Kemlock Server are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project will follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) from its first release.

Releases are generated from [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/#specification):
the notes on each [GitHub release](https://github.com/Arsslensoft/Kemlock-Server/releases) list the
merged changes by their commit titles. This file keeps the summary that people read first.

## [Unreleased]

## [0.1.0] - 2026-11-24

The first release.

### Added

- Server
  - One Rust binary (axum, SeaORM) built from clean-architecture crates: domain, application,
    crypto, storage, blob, identity, notifications and federation adapters, and the API crates.
  - SQLite by default, PostgreSQL or MySQL when wanted; migrations run forward at start-up.
  - A first-run setup page protected by a one-time setup code, instead of an admin token.
  - Health endpoints, a `/.well-known/security.txt`, and settings that use Vaultwarden's names.
- Kemlock API
  - Every Kemlock kind of item, with ML-KEM-1024 + X25519 key sharing and ML-DSA-65 + Ed25519
    signatures; the byte formats are in `docs/crypto.md`.
- Bitwarden API
  - Answers as Vaultwarden does, so Bitwarden apps and Amethystora Vault keep syncing; two-step
    login with authenticator apps, security keys, emailed codes, YubiKey and Duo.
  - Bitwarden clients up to 2026.10, including the user key id and minimum KDF steps they take
    at sign-in.
  - Contract tests that replay the traffic of the Kemlock app and Amethystora Vault.
- Migration
  - Import of a Vaultwarden data folder as stored, with nothing decrypted, and importers ported
    from Bitwarden's (see `crates/kemlock-import/NOTICE`).
- Federation
  - Servers copy chosen vaults to each other as ciphertext (`docs/federation.md`), and Kemlock apps
    fall back to a replica when a vault's home server is down.
- Sign-in
  - OpenID Connect SSO without key escrow: a trusted device, an approval from another device or
    the master password opens the vault.
- Web
  - A React and TypeScript web vault and admin console, built into the server binary, with its
    cryptography in WebAssembly in a Web Worker.
- Push
  - A contract with the hosted push relay for closed apps (`docs/push-relay.md`).
- Packaging
  - Multi-arch container images (`ghcr.io/arsslensoft/kemlock-server`) and static binaries for the
    architectures Vaultwarden supports, with a script to rebuild a release and compare it
    (`tools/verify.sh`).
- Quality and security
  - CI with fmt, clippy, tests, `cargo-deny`, `cargo-vet` and `cargo-audit`; fuzzing of the parsers
    of untrusted bytes; cross-implementation test vectors; load and performance tests.
  - A security policy that reports through GitHub security advisories (`SECURITY.md`).
- Project
  - Contributing guide, DCO, code of conduct, governance, maintainers, support page, issue forms,
    a pull request template and code owners.

[Unreleased]: https://github.com/Arsslensoft/Kemlock-Server/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Arsslensoft/Kemlock-Server/releases/tag/v0.1.0
