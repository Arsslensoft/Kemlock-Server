//! Contract tests for the Bitwarden API of Kemlock Server.
//!
//! Kemlock's app and Amethystora Vault were built and tested against Vaultwarden 1.37.5, so the
//! Bitwarden API answers every route they call exactly as Vaultwarden does, quirks included. Each
//! test in `tests/` pins one of those answers over plain HTTP and cites, in a comment, the file and
//! line of the app or Amethystora code that depends on it. The messages of the assertions say what
//! Vaultwarden does, so a failure reads as a difference, not as a bare "false".
//!
//! # Where the server is
//!
//! - By default [`server::target`] starts the real `kemlock-server` in this process, on an ephemeral
//!   port of `127.0.0.1`, with a temporary SQLite database, signups on and Bitwarden compatibility
//!   on (`KEMLOCK_BITWARDEN_COMPAT=true`).
//! - With `KEMLOCK_CONTRACT_URL=http://host:port` the same tests run against that server. A real
//!   Vaultwarden 1.37.5 is how the tests themselves are checked: start it with
//!   `DOMAIN=<that address>`, `SIGNUPS_ALLOWED=true`, `SIGNUPS_VERIFY=false` and its login and
//!   unauthenticated rate limits raised (`LOGIN_RATELIMIT_MAX_BURST=1000`, say), and set
//!   `KEMLOCK_CONTRACT_VAULTWARDEN=1` so the tests that pin only what this design decided differently
//!   (tighter KDF bounds) stand aside. The address must be plain `http`: the client has no TLS.
//!
//! # What is here
//!
//! - [`http`]: a small HTTP/1.1 client over `hyper-util`, and [`http::Session`], one signed-in account.
//! - [`account`]: registering an account through the web vault's routes, and the token form.
//! - [`enc`]: strings shaped like Bitwarden's encrypted strings. The server never decrypts, so the
//!   tests carry no cryptography: only the shape `2.<iv>|<ciphertext>|<mac>` matters to it.
//! - [`shape`]: the structural comparator for the fixtures.
//! - [`files`]: the two steps of an attachment upload.
//! - [`fixtures`], [`totp`], [`webauthn`], [`util`]: the recorded answers, an authenticator code, a
//!   security key's registration and small checks.

pub mod account;
pub mod enc;
pub mod files;
pub mod fixtures;
pub mod http;
pub mod server;
pub mod shape;
pub mod totp;
pub mod util;
pub mod webauthn;

pub use account::{Account, Kdf};
pub use http::{Call, Http, Reply, Session};
pub use server::{Target, target};

/// A client for the server under test. Each test makes its own: a client belongs to the runtime
/// that made it, and every `#[tokio::test]` has a runtime of its own.
pub fn client() -> Http {
    Http::new(&target().base)
}

/// A new account with cheap PBKDF2 settings, registered and signed in.
pub async fn fresh_session() -> Session {
    let http = client();
    let account = http.register_ok(Kdf::cheap_pbkdf2()).await;
    http.login(&account).await
}

/// True, with a note on stderr, when the tests run against a real Vaultwarden and `why` is a rule
/// this design chose differently. The test that asks returns at once.
pub fn stand_aside_on_vaultwarden(why: &str) -> bool {
    let aside = target().vaultwarden;
    if aside {
        eprintln!("skipped on Vaultwarden: {why}");
    }
    aside
}
