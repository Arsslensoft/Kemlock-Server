//! The personal API key of a Compatible account: what the Bitwarden CLI and scripts sign in with
//! (`client_id` `user.<id>`, `client_secret`, scope `api`).
//!
//! The key lives in the account's `BwAccount` row, as Vaultwarden keeps it in `users.api_key`,
//! and the Bitwarden API's `POST /api/accounts/api-key` makes it on first ask. These use cases
//! are the same key seen from the Kemlock API; the caller has checked a fresh proof. An account
//! with no Bitwarden record (made through the Kemlock sign-in alone) has no key: `NotFound`.

use crate::bitwarden::{BwAccount, BwAccountRepo};
use crate::error::AppError;
use crate::ports::{Clock, Random};
use kemlock_domain::UserId;

/// Length of a key, as Vaultwarden makes it.
pub const API_KEY_LEN: usize = 30;

/// The key and what names it.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiKey {
    /// `user.<uuid>`.
    pub client_id: String,
    /// The secret: never logged.
    pub client_secret: String,
    /// The account's revision date, milliseconds since the epoch.
    pub revision_ms: i64,
    /// Whether this call made the key.
    pub created: bool,
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKey")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

/// `user.<uuid>`: the `client_id` of an account's key.
pub fn client_id(user: UserId) -> String {
    format!("user.{}", user.0)
}

/// A random string over `[A-Za-z0-9]`. Bytes above the largest multiple of 62 are redrawn so every
/// character is equally likely.
pub fn random_key<R: Random>(random: &R, len: usize) -> String {
    const ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(len);
    while out.len() < len {
        for byte in random.bytes::<32>() {
            if out.len() == len {
                break;
            }
            if byte < 248 {
                out.push(char::from(ALPHABET[usize::from(byte) % 62]));
            }
        }
    }
    out
}

#[derive(Debug)]
pub struct ApiKeys<R, E> {
    pub accounts: R,
    pub env: E,
}

impl<R: BwAccountRepo, E: Clock + Random> ApiKeys<R, E> {
    async fn account(&self, user: UserId) -> Result<BwAccount, AppError> {
        self.accounts.get(user).await?.ok_or(AppError::NotFound)
    }

    /// Whether the account has a key yet, and its `client_id`; never the secret.
    pub async fn show(&self, user: UserId) -> Result<(String, bool), AppError> {
        let account = self.account(user).await?;
        Ok((client_id(user), account.api_key.is_some()))
    }

    /// The key, made first when there is none.
    pub async fn reveal(&self, user: UserId) -> Result<ApiKey, AppError> {
        let account = self.account(user).await?;
        if account.api_key.is_some() {
            return self.view(account, false);
        }
        self.replace(account, true).await
    }

    /// A new key in place of the old: the old secret stops working at once.
    pub async fn rotate(&self, user: UserId) -> Result<ApiKey, AppError> {
        let account = self.account(user).await?;
        self.replace(account, false).await
    }

    async fn replace(&self, mut account: BwAccount, created: bool) -> Result<ApiKey, AppError> {
        let user = account.user;
        account.api_key = Some(random_key(&self.env, API_KEY_LEN));
        self.accounts.update(&account).await?;
        // Bitwarden clients sync on the new revision date, as after any change.
        let now_ms =
            i64::try_from(self.env.now().unix_timestamp_nanos() / 1_000_000).unwrap_or(i64::MAX);
        self.accounts.touch(user, now_ms).await?;
        let account = self.account(user).await?;
        self.view(account, created)
    }

    fn view(&self, account: BwAccount, created: bool) -> Result<ApiKey, AppError> {
        let secret = account.api_key.ok_or(AppError::NotFound)?;
        Ok(ApiKey {
            client_id: client_id(account.user),
            client_secret: secret,
            revision_ms: account.revision_ms,
            created,
        })
    }
}
