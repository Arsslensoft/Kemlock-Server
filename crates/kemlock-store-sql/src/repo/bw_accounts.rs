//! `BwAccountRepo` on `bw_accounts`.

use crate::error::StoreResult;
use crate::store::SqlStore;
use crate::tables::bw_accounts;
use kemlock_app::b64url;
use kemlock_app::bitwarden::{BwAccount, BwAccountRepo};
use kemlock_app::ports::StoreError;
use kemlock_domain::UserId;
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

/// How many times `touch` retries after losing a race for the revision date.
const TOUCH_TRIES: usize = 8;

/// The `ServerSeal` purpose of a personal API key at rest.
const API_KEY_PURPOSE: &str = "bw-api-key";
/// What a sealed key starts with in `bw_accounts.api_key`; a key without it is a plain one, from
/// before keys were sealed or from the move from Vaultwarden.
const SEALED_PREFIX: &str = "sealed:";

impl SqlStore {
    /// The text kept for an API key: sealed under `server.key` once the store has the seal.
    fn kept_api_key(&self, key: &str) -> String {
        match self.secret_seal() {
            Some(seal) => format!(
                "{SEALED_PREFIX}{}",
                b64url::encode(&seal.seal(API_KEY_PURPOSE, key.as_bytes()))
            ),
            None => key.to_owned(),
        }
    }

    /// Seals every API key still stored plain (an older database, or the move from Vaultwarden),
    /// once, at start-up after the seal is set, so none waits on being read to be sealed. Returns
    /// how many it sealed; without a seal it does nothing.
    pub async fn seal_stored_secrets(&self) -> Result<u64, StoreError> {
        if self.secret_seal().is_none() {
            return Ok(0);
        }
        let plain = bw_accounts::Entity::find()
            .filter(bw_accounts::Column::ApiKey.is_not_null())
            .filter(bw_accounts::Column::ApiKey.not_like(format!("{SEALED_PREFIX}%")))
            .all(self.writer())
            .await
            .store()?;
        let mut sealed = 0;
        for row in plain {
            let Some(key) = row.api_key else {
                continue;
            };
            let moved = bw_accounts::Entity::update_many()
                .col_expr(
                    bw_accounts::Column::ApiKey,
                    Expr::value(self.kept_api_key(&key)),
                )
                .filter(bw_accounts::Column::UserId.eq(row.user_id))
                .filter(bw_accounts::Column::ApiKey.eq(key.as_str()))
                .exec(self.writer())
                .await
                .store()?;
            sealed += moved.rows_affected;
        }
        Ok(sealed)
    }

    /// The key a stored value holds. A plain one is returned as it is and sealed in the row, so
    /// the keys of an older database are sealed as they are read. A sealed one that doesn't open
    /// (the database came back with another `server.key`) is no key: its owner makes a new one,
    /// and the account stays signed in to everything else.
    async fn shown_api_key(&self, user: UserId, stored: String) -> Option<String> {
        let Some(sealed) = stored.strip_prefix(SEALED_PREFIX) else {
            if self.secret_seal().is_some() {
                let moved = bw_accounts::Entity::update_many()
                    .col_expr(
                        bw_accounts::Column::ApiKey,
                        Expr::value(self.kept_api_key(&stored)),
                    )
                    .filter(bw_accounts::Column::UserId.eq(user.0))
                    .filter(bw_accounts::Column::ApiKey.eq(stored.as_str()))
                    .exec(self.writer())
                    .await;
                if let Err(error) = moved {
                    tracing::warn!(%error, "couldn't seal a stored API key");
                }
            }
            return Some(stored);
        };
        let opened = self.secret_seal().and_then(|seal| {
            let bytes = b64url::decode(sealed)?;
            seal.open(API_KEY_PURPOSE, &bytes).ok()
        });
        let key = opened.and_then(|bytes| String::from_utf8(bytes.to_vec()).ok());
        if key.is_none() {
            tracing::warn!(%user, "a stored API key doesn't open; it is treated as none");
        }
        key
    }
}

impl BwAccountRepo for SqlStore {
    async fn get(&self, user: UserId) -> Result<Option<BwAccount>, StoreError> {
        let Some(row) = bw_accounts::Entity::find_by_id(user.0)
            .one(self.reader())
            .await
            .store()?
        else {
            return Ok(None);
        };
        let mut account = row.into_domain()?;
        if let Some(stored) = account.api_key.take() {
            account.api_key = self.shown_api_key(user, stored).await;
        }
        Ok(Some(account))
    }

    async fn insert(&self, account: &BwAccount) -> Result<(), StoreError> {
        let row = bw_accounts::ActiveModel {
            api_key: Set(account.api_key.as_deref().map(|k| self.kept_api_key(k))),
            ..bw_accounts::active(account)
        };
        bw_accounts::Entity::insert(row)
            .exec(self.writer())
            .await
            .store()?;
        Ok(())
    }

    async fn update(&self, account: &BwAccount) -> Result<(), StoreError> {
        let row = bw_accounts::ActiveModel {
            user_id: NotSet,
            revision_ms: NotSet,
            api_key: Set(account.api_key.as_deref().map(|k| self.kept_api_key(k))),
            ..bw_accounts::active(account)
        };
        let result = bw_accounts::Entity::update_many()
            .set(row)
            .filter(bw_accounts::Column::UserId.eq(account.user.0))
            .exec(self.writer())
            .await
            .store()?;
        if result.rows_affected == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Reads the revision date, then moves it with a compare-and-set, so two racing changes each
    /// take a different value.
    async fn touch(&self, user: UserId, now_ms: i64) -> Result<i64, StoreError> {
        let writer = self.writer();
        for _ in 0..TOUCH_TRIES {
            let row = bw_accounts::Entity::find_by_id(user.0)
                .one(writer)
                .await
                .store()?
                .ok_or(StoreError::NotFound)?;
            let next = now_ms.max(row.revision_ms.saturating_add(1));
            let result = bw_accounts::Entity::update_many()
                .col_expr(bw_accounts::Column::RevisionMs, Expr::value(next))
                .filter(bw_accounts::Column::UserId.eq(user.0))
                .filter(bw_accounts::Column::RevisionMs.eq(row.revision_ms))
                .exec(writer)
                .await
                .store()?;
            if result.rows_affected == 1 {
                return Ok(next);
            }
        }
        Err(StoreError::Backend(
            "the account's revision date kept changing under a touch".to_owned(),
        ))
    }
}
