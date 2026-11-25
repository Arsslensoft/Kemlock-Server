# Changelog

All notable changes to Kemlock Server are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project will follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) from its first release.

Releases are generated from [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/#specification):
the notes on each [GitHub release](https://github.com/Arsslensoft/Kemlock-Server/releases) list the
merged changes by their commit titles. This file keeps the summary that people read first.

## [Unreleased]

## [0.1.2] - 2026-11-25

### Added

- Send an item from the vault, of any kind, as a link. It travels as an encrypted text Send, so
  Bitwarden apps still open it as text.
- A "Where to find the setup code" panel on the first setup screen, for each way the server runs.

### Changed

- The Kemlock wordmark, not the app icon, in every header.
- Alerts and banners glow softly in their own colour, as in the mobile app; not with reduced
  motion.
- Settings forms in the admin console and setup: the label above each control, short fields two
  to a row, switches before their label, ranges as placeholders with validation that blocks Save,
  one "Save" per section with "Saved." under its title, and Discard only when something changed.
- Other ways to sign in show as compact tiles; username and password sit side by side.

### Fixed

- Pairing a server takes its full `https://` address, IPv6 included, and a code typed with spaces.

## [0.1.1] - 2026-11-24

### Added

- Web vault
  - Forms to add and edit every kind of item: one-time codes, backup codes, cards, identities,
    SSH keys (made in the browser or pasted), PGP keys, certificates and contacts.
  - Sign-in with SSO, a passkey or an approval from another device, and unlock with an approval.
  - Setup with a security key or a passkey as the admin's second step.
  - Account security sets up passkeys, security keys, YubiKey, Duo, an emailed code and the
    recovery code. A step can be added beside another one after a fresh proof.
  - The Recovery Kit: three printable pieces, any two of which unlock the vault, in the Kemlock
    app's format.
  - The about page names the author and links to the contributors.
- Server
  - Routes for email, YubiKey and Duo two-step setup, security keys, the Recovery Kit and vault
    placement (`GET /kem/v1/placement`).
  - First-run "Server basics" (who may join, the mail server) are saved when setup finishes.
  - `kemlock-cli reset-admin`, with `--promote <email>`.

### Changed

- Removing a second step, and showing the recovery code, need a fresh proof.
- The source code link is on the about page only.

### Fixed

- Items saved from the web vault carry the entry id and epoch-millisecond times the Kemlock app
  reads, so the app shows them and keeps web edits when it syncs.
- The setup screen's passkey and security key choices can be picked.
- A held federation promotion that would take a vault's home from this server.
- Proxmox setup: the setup code, a turned-off Caddy on update, and Alpine settings.

### Security

- An authenticator code works once as a proof, as it does at sign-in.
- The passkey page for the browser extension builds its redirect from the allowlist, never from
  the caller's address.
- The release build installs Zig from a hash-pinned requirements file.

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

[Unreleased]: https://github.com/Arsslensoft/Kemlock-Server/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/Arsslensoft/Kemlock-Server/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Arsslensoft/Kemlock-Server/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Arsslensoft/Kemlock-Server/releases/tag/v0.1.0
