# Changelog

All notable changes to Kemlock Server are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project will follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) from its first release.

Releases are generated from [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/#specification):
the notes on each [GitHub release](https://github.com/Arsslensoft/Kemlock-Server/releases) list the
merged changes by their commit titles. This file keeps the summary that people read first.

## [Unreleased]

## [0.1.4] - 2026-11-26

### Added

- An avatar menu at the top right: Profile, Security, Devices & apps, Admin console for admins,
  About, Lock the vault and Sign out. The admin console has its own, with My Vault, About and
  Sign out.
- A New menu with every item type, each with its own form. Edit opens the same form, filled in.
- The sidebar lists All items and the 12 types with their counts. Each type has its own page.
- A Vault column and filter on All items, every type page, Trash (with "Deleted from") and
  Duplicates.
- Duplicates covers every type and gives a reason for each group. For an item in two places, you
  pick which vault keeps it.
- New item kinds: File (encrypted in the browser and counted against the quota) and Contact (a
  person, with an optional PGP public key).
- Linked items. A link shows on both items, and unlinking either side removes both ends.
- Card numbers are grouped by brand and checked with Luhn, and the brand is found from the number.
- Profile changes your name, your sign-in email and your master password. A new email applies once
  the link sent to it is opened. When two-step is on, the password and email changes ask for its
  code. Accounts that sign in with SSO can't edit their name or email.
- Devices & apps marks trusted Kemlock apps with a shield, and each device has a menu. Connect shows
  the server's public address, with Copy.
- An admin Custom fields page for fields every item can use, with up to 100 fields, and a setting
  for whether people may add their own. Every custom field is optional.

### Changed

- "Code" is now "MFA code" everywhere. The stored kind is still `otp`.
- An item page has one main button, Edit. The other actions are in a ⋯ menu.
- A round lock with a tooltip replaces the "End-to-end encrypted" card.
- Only secure notes take attachments.
- The admin Overview's stats are reworked, and each switch in Server settings has a hint under it.
- Items get new optional members: links, the `file` kind, a contact's person fields and references
  to admin fields. Existing items stay byte for byte. `docs/crypto.md` lists every addition.

### Fixed

- "Confirm it's you" asks only for the second steps the account has set up, and takes a security
  key. An admin whose only second step is a security key can confirm admin changes again.
- Setup makes the passkey that was ticked when the second step is a security key, and saves the key
  as "Security key".
- "Go to the admin console" after setup opens the console instead of the vault.
- When a password or email changes, refresh tokens and the security stamp are rotated, and tokens
  of removed devices are refused.
- A change of email can't show whether another account already has the address.
- Emergency access grants follow an email change.
- Concurrent requests can't undo a password change or a rename.

## [0.1.3] - 2026-11-25

### Added

- An API key for the Bitwarden CLI and scripts, shown and rotated in Account security behind a fresh
  check. Rotating it stops the old one at once.
- Delete account, from the web vault and on the Bitwarden routes as Vaultwarden has them. The last
  owner of an organisation is refused, and the account's copies on paired servers are deleted too.
- A security key or passkey answers the "Confirm it's you" check wherever one is asked.
- File Sends are copied to paired servers, encrypted. A Send with a view limit is opened only on its
  home server.
- Paired servers are checked every `KEMLOCK_FEDERATION_PROBE_SECONDS` (60 by default): online,
  slow, offline, or a key that does not match. "Where your vault is stored" shows what was found.
- Changes waiting for an offline server can be held back from it, per vault, and offered again.
- A detail page for each newer item kind, with secrets masked until shown.
- The Send list marks Sends made from a vault item.
- Scanning the Recovery Kit's QR code works in Firefox.
- The server sends mobile pushes itself. iPhones are pushed to through Apple with your own APNs key
  (`KEMLOCK_APNS_KEY_FILE`, `KEMLOCK_APNS_KEY_ID`, `KEMLOCK_APNS_TEAM_ID`, and optionally
  `KEMLOCK_APNS_TOPIC` and `KEMLOCK_APNS_SANDBOX`); Android phones through UnifiedPush, which needs
  no setting. A push says only "sync now".
- The admin console's Push card shows both, with the hosted relay under them.

### Changed

- Push relays and backups are settings in the admin console, applied without a restart. Their
  secrets are kept sealed and never shown again. `DOMAIN` and `DATA_FOLDER` stay configuration,
  and Server settings shows the address chosen at setup beside the one in use.
- The other ways to sign in are full-width buttons again, one under the other.
- Move from Vaultwarden, Users and peer security follow the settings form layout.
- Each settings group's Save button is named after its group for screen readers.
- Kemlock's hosted push relay is now an optional fallback for iPhones on a server with no Apple key.
  It stays off unless you turn it on.
- A device registers a push token of kind `apns` or `unifiedpush`. `fcm` is no longer accepted (a
  400), and nothing is sent to old `fcm` tokens: Kemlock uses no Firebase.
- `GET /admin/v1/push-relay` also answers `apnsConfigured`, `apnsSandbox` and `unifiedPush`.
- UnifiedPush endpoints must be `https` on port 443 or 8443, an account may register 20 of them, and
  `KEMLOCK_UNIFIEDPUSH_ALLOW_PRIVATE=true` lets the server push to endpoints on a private network
  (a ntfy on your LAN).
- Upgrade all replicas together. A replica still on the previous binary errors on the `unifiedpush`
  push-token rows the new one stores.

### Fixed

- A reload keeps you signed in, and the About dialog returns to the page you were on.
- Admin lists keep focus while you search, and an item's back button returns to the list.
- Locking or signing out also forgets the admin console's recent check.
- Saving one settings group keeps the unsaved edits in the others, and saving a new secret clears
  its field and shows "Saved.".
- Sends are not created twice, deleting one asks first, and forms clear only once saved.
- The Proxmox install no longer stops before the server has printed its setup code.

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

[Unreleased]: https://github.com/Arsslensoft/Kemlock-Server/compare/v0.1.4...HEAD
[0.1.4]: https://github.com/Arsslensoft/Kemlock-Server/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/Arsslensoft/Kemlock-Server/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/Arsslensoft/Kemlock-Server/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Arsslensoft/Kemlock-Server/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Arsslensoft/Kemlock-Server/releases/tag/v0.1.0
