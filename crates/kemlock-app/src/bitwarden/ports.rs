//! The Bitwarden account record and its repository port.
//!
//! `User` has no room for Vaultwarden's password hash, its client KDF settings or the wrapped
//! keys Bitwarden apps hold, so they live here, keyed by the same user id. A user with a
//! `BwAccount` is a Compatible account (design, "One account, two front doors").

use crate::ports::StoreError;
use kemlock_domain::UserId;
use std::future::Future;

/// Vaultwarden's per-account values.
#[derive(Clone, PartialEq, Eq)]
pub struct BwAccount {
    pub user: UserId,
    /// PBKDF2-HMAC-SHA256 of the client's `masterPasswordHash` (as the text the client sent) with
    /// `salt` and `password_iterations`. Empty for an account with no password.
    pub password_hash: Vec<u8>,
    /// 64 random bytes made at registration.
    pub salt: Vec<u8>,
    /// The server-side PBKDF2 rounds of `password_hash`; 600,000 for a new hash.
    pub password_iterations: u32,
    /// The client's KDF: 0 is PBKDF2-SHA256, 1 is Argon2id.
    pub kdf_type: i32,
    pub kdf_iterations: i32,
    /// Argon2id memory in MiB.
    pub kdf_memory: Option<i32>,
    pub kdf_parallelism: Option<i32>,
    /// The user key, wrapped under the master key, as the client made it (`2.…|…|…`).
    pub akey: String,
    /// The RSA private key wrapped under the user key.
    pub private_key: Option<String>,
    /// The RSA public key, base64 DER.
    pub public_key: Option<String>,
    pub password_hint: Option<String>,
    /// The personal API key, `client_credentials` with `client_id` `user.<id>`.
    pub api_key: Option<String>,
    pub avatar_color: Option<String>,
    /// The account's revision date in milliseconds since the Unix epoch: it moves on every change
    /// the Bitwarden API makes, so `/api/accounts/revision-date` tells clients to sync.
    pub revision_ms: i64,
}

impl std::fmt::Debug for BwAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BwAccount")
            .field("user", &self.user)
            .field("kdf_type", &self.kdf_type)
            .finish_non_exhaustive()
    }
}

pub trait BwAccountRepo: Send + Sync {
    fn get(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<Option<BwAccount>, StoreError>> + Send;

    /// Inserts a new record; `Duplicate` when the user has one, `NotFound` when there is no such
    /// user.
    fn insert(&self, account: &BwAccount) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Replaces every value but the revision date, which only `touch` moves; `NotFound` when the
    /// user has no record.
    fn update(&self, account: &BwAccount) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Moves the revision date to `max(now_ms, current + 1)` and returns it, so two changes in one
    /// millisecond still differ. `NotFound` when the user has no record.
    fn touch(
        &self,
        user: UserId,
        now_ms: i64,
    ) -> impl Future<Output = Result<i64, StoreError>> + Send;
}

/// The id of an account's user key: 32 lowercase hex digits, as Bitwarden's `KeyId`. Bitwarden
/// clients from 2026.10 read it in `/api/sync` and report it once when the server holds none
/// (`POST /api/accounts/key-management/user-key-id`).
pub trait BwUserKeyIdRepo: Send + Sync {
    /// The id, from the account's own record or, for an account moved from Vaultwarden, from
    /// its imported row.
    fn user_key_id(
        &self,
        user: UserId,
    ) -> impl Future<Output = Result<Option<String>, StoreError>> + Send;

    /// Records `key_id` unless the account has one already, in either place. `false` means it
    /// has one and nothing was written.
    fn put_user_key_id_if_absent(
        &self,
        user: UserId,
        key_id: &str,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
}

/// Tries made at one secret of one account (a second-step code, a request for an emailed code),
/// counted in a window and kept in the database, so a guess can't be made at the speed of the
/// network by many addresses, and a restart doesn't give the tries back. A caller counts a try
/// before it checks the secret, so tries that arrive together are each counted.
pub trait BwTryRepo: Send + Sync {
    /// Counts one try of `kind` for `user` at `now` (Unix seconds) and returns how many tries the
    /// window holds, this one included. A window begins at its first try and ends `window_secs`
    /// seconds later; the first try after that begins a new one. `NotFound` when there is no such
    /// user.
    fn count_try(
        &self,
        user: UserId,
        kind: &str,
        now: i64,
        window_secs: i64,
    ) -> impl Future<Output = Result<u32, StoreError>> + Send;

    /// Forgets the tries of `kind` for `user`, as a right answer does.
    fn forget_tries(
        &self,
        user: UserId,
        kind: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}
