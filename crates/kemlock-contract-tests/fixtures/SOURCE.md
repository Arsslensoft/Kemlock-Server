# Where these fixtures come from

Copied byte for byte from the Kemlock app, `Arsslensoft/Kemlock`, folder
`mobile/test/fixtures/vaultwarden/`, at its commit
`7ee88debc3084f1fcd0c5e3d1bdf34199934a9f9` (the last commit that touched the folder is
`eb9c6e85ad993db1563a4b5635a67f6ebed6e5d1`, 2026-11-21). They are what Vaultwarden 1.37.5 and the
Bitwarden CLI 2026.6.0 made or took, so never edit or regenerate them here: copy the folder again
from the app and change this note.

| File | What it pins | Used by |
|---|---|---|
| `account-pbkdf2.json`, `account-argon2id.json` | prelogin, token and `/api/sync` answers (`profile`, `folders`, `ciphers`) of a real Vaultwarden account, with the CLI-made items and what each holds | `tests/identity.rs` (prelogin, token), `tests/sync.rs` (sync) |
| `formats.json`, `vault-items.json` | the strings Kemlock writes into items | `tests/formats.rs` |
| `webauthn/` | the security-key challenge (`providers2-7*.json`) and the token Vaultwarden took, with the rules it kept (README) | `tests/webauthn.rs` |
| `browser/` | what the web vault's connector pages answer for a browser extension (README) | nothing yet: for the web vault's own gate |

Keep the folder's own READMEs (`webauthn/README.md`, `browser/README.md`) beside the files: they say
which server and which version made them.

`.gitattributes` marks `**/fixtures/**` as `-text`, so a Windows checkout never rewrites a line end
in them.
